'use strict';

const { Contract } = require('fabric-contract-api');
const snarkjs = require('snarkjs');
const circomlibjs = require('circomlibjs');
const faceVKey = require('./verification_key.json');
const irisVKey = require('./iris_verification_key.json');
const enrollVKey = require('./enroll_verification_key.json');
const ballotCrypto = require('./ballotCrypto');
const tallyCrypto = require('./tallyCrypto');

// Only the Registration Authority's organisation may enrol voters,
// register ballots and close them. Override with REGISTRAR_MSPS="Org1MSP,OtherMSP".
const REGISTRAR_MSPS = (process.env.REGISTRAR_MSPS || 'Org1MSP').split(',').map((s) => s.trim());

// Public signal layout (set by the circom `main` declarations):
//   [valid, merkleRoot, nullifier, electionId, voteBinding, sensorRoot]
const PS = { VALID: 0, ROOT: 1, NULLIFIER: 2, ELECTION_ID: 3, VOTE_BINDING: 4, SENSOR_ROOT: 5, LENGTH: 6 };

// Attested-enrollment public signals (enroll_auth.circom): [commitment, nidField, sensorRoot]
const ENROLL_PS = { COMMITMENT: 0, NID_FIELD: 1, SENSOR_ROOT: 2, LENGTH: 3 };

// Depth of the authorised capture-device registry (must match the circuits)
const SENSOR_TREE_LEVELS = 10;

let _poseidon = null;
let _F = null;

async function initPoseidon() {
  if (!_poseidon) {
    _poseidon = await circomlibjs.buildPoseidon();
    _F = _poseidon.F;
  }
  return { poseidon: _poseidon, F: _F };
}

async function poseidonHash2(left, right) {
  const { poseidon, F } = await initPoseidon();
  const h = poseidon([F.e(left), F.e(right)]);
  return F.toObject(h);
}

class IdentityContract extends Contract {

  // Helper: Build sparse Merkle tree root on-chain
  async buildMerkleTreeOnChain(commitments, MERKLE_TREE_LEVELS = 20) {

    // 1. Get zero hashes
    const zeroHashes = [0n];
    for (let i = 0; i < MERKLE_TREE_LEVELS; i++) {
      zeroHashes.push(await poseidonHash2(zeroHashes[i], zeroHashes[i]));
    }
    
    // 2. Layer 0: store commitments as BigInt
    const layers = [new Map()];
    for (let i = 0; i < commitments.length; i++) {
      const val = BigInt(commitments[i]);
      if (val !== 0n) {
        layers[0].set(i, val);
      }
    }
    
    // 3. Build tree bottom-up
    for (let level = 0; level < MERKLE_TREE_LEVELS; level++) {
      const nextLayer = new Map();
      const currentLayer = layers[level];
      
      const parentIndices = new Set();
      for (const idx of currentLayer.keys()) {
        parentIndices.add(Math.floor(idx / 2));
      }
      
      for (const parentIdx of parentIndices) {
        const leftIdx = parentIdx * 2;
        const rightIdx = parentIdx * 2 + 1;
        const left = currentLayer.has(leftIdx) ? currentLayer.get(leftIdx) : zeroHashes[level];
        const right = currentLayer.has(rightIdx) ? currentLayer.get(rightIdx) : zeroHashes[level];
        nextLayer.set(parentIdx, await poseidonHash2(left, right));
      }
      
      layers.push(nextLayer);
    }
    
    const root = layers[MERKLE_TREE_LEVELS].has(0)
      ? layers[MERKLE_TREE_LEVELS].get(0)
      : zeroHashes[MERKLE_TREE_LEVELS];
      
    return root;
  }

  // Initialize ledger
  async initLedger(ctx) {
    console.log('============= START : Initialize Ledger ===========');
    
    // Initialize global face commitments storage
    const commitmentsStore = {
      commitments: [],
      docType: 'commitments'
    };
    await ctx.stub.putState('GLOBAL_COMMITMENTS', Buffer.from(JSON.stringify(commitmentsStore)));

    // Initialize global iris commitments storage (independent Merkle tree)
    const irisCommitmentsStore = {
      commitments: [],
      docType: 'iris_commitments'
    };
    await ctx.stub.putState('GLOBAL_IRIS_COMMITMENTS', Buffer.from(JSON.stringify(irisCommitmentsStore)));
    
    console.log('Identity verification and voting ledger initialized (Merkle + Nullifier, face + iris)');
    console.log('============= END : Initialize Ledger ===========');
  }

  // ============================
  // REGISTRATION FUNCTIONS
  // ============================

  _assertRegistrar(ctx) {
    const msp = ctx.clientIdentity.getMSPID();
    if (!REGISTRAR_MSPS.includes(msp)) {
      throw new Error(`Access denied: ${msp} is not an authorised registrar organisation`);
    }
  }

  // Register a new voter by adding their Poseidon commitment
  // Face enrollment is attested (FINDINGS C26): the proof shows that
  // `commitment` opens to the template a registered kiosk captured and
  // signed for this NID, so the RA no longer has to trust that the client's
  // commitment encodes the enrollee's own face (attack A25).
  async register(ctx, nidHash, commitment, enrollProofJSON, enrollSignalsJSON) {
    console.log('============= START : Register Identity ===========');
    this._assertRegistrar(ctx);

    // Validate inputs
    if (!nidHash || !commitment || !enrollProofJSON || !enrollSignalsJSON) {
      throw new Error('All parameters (nidHash, commitment, enrollProof, enrollSignals) are required');
    }
    await this._verifyEnrollment(ctx, nidHash, commitment, enrollProofJSON, enrollSignalsJSON);

    // Check if already registered (by NID)
    const exists = await this.userExists(ctx, nidHash);
    if (exists) {
      throw new Error(`Identity with NID hash ${nidHash} is already registered`);
    }

    // Get deterministic timestamp from transaction
    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    // Create identity object
    const identity = {
      nidHash,
      commitment,
      registeredAt: timestampStr,
      docType: 'identity'
    };

    // Store in ledger (per-user storage for duplicate checking)
    await ctx.stub.putState(nidHash, Buffer.from(JSON.stringify(identity)));

    // Add commitment to global commitments list
    await this._addCommitment(ctx, commitment, timestampStr);

    // Emit registration event
    const eventPayload = {
      nidHash,
      commitment,
      timestamp: timestampStr
    };
    
    await ctx.stub.setEvent('Registered', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Identity registered: ${nidHash}`);
    console.log(`Commitment: ${commitment.slice(0, 20)}...`);
    console.log('============= END : Register Identity ===========');

    return JSON.stringify(identity);
  }

  // Check if user exists
  async userExists(ctx, nidHash) {
    const identityBytes = await ctx.stub.getState(nidHash);
    return identityBytes && identityBytes.length > 0;
  }

  // ============================
  // INCREMENTAL VOTER TREE
  // Append-only Poseidon tree of depth 20 kept as "filled subtrees"
  // (Tornado/Semaphore style): O(L) per registration, O(1) root lookup per
  // vote. Same tree as buildMerkleTreeOnChain (zero leaf 0, empty-subtree
  // digests z[i]) — leaves are inserted in registration order.
  // ============================

  async _zeroHashes(levels = 20) {
    const z = [0n];
    for (let i = 0; i < levels; i++) z.push(await poseidonHash2(z[i], z[i]));
    return z;
  }

  async _treeState(ctx, bioType) {
    const key = bioType === 'iris' ? 'MERKLE_IRIS' : 'MERKLE_FACE';
    const bytes = await ctx.stub.getState(key);
    if (bytes && bytes.length > 0) return JSON.parse(bytes.toString());

    // First use on a ledger that predates the incremental tree: build it
    // once from the existing commitment list, then persist it.
    const z = await this._zeroHashes();
    const state = { nextIndex: 0, filled: z.slice(0, 20).map(String), root: z[20].toString() };
    const listKey = bioType === 'iris' ? 'GLOBAL_IRIS_COMMITMENTS' : 'GLOBAL_COMMITMENTS';
    const listBytes = await ctx.stub.getState(listKey);
    if (listBytes && listBytes.length > 0) {
      for (const c of JSON.parse(listBytes.toString()).commitments) await this._treeAppend(state, BigInt(c.value), z);
    }
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(state)));
    return state;
  }

  async _treeAppend(state, leaf, z) {
    let idx = state.nextIndex;
    let cur = leaf;
    for (let i = 0; i < 20; i++) {
      if (idx % 2 === 0) {
        state.filled[i] = cur.toString();
        cur = await poseidonHash2(cur, z[i]);
      } else {
        cur = await poseidonHash2(BigInt(state.filled[i]), cur);
      }
      idx = Math.floor(idx / 2);
    }
    state.root = cur.toString();
    state.nextIndex += 1;
  }

  async _treeInsert(ctx, bioType, commitment) {
    const state = await this._treeState(ctx, bioType);
    await this._treeAppend(state, BigInt(commitment), await this._zeroHashes());
    await ctx.stub.putState(bioType === 'iris' ? 'MERKLE_IRIS' : 'MERKLE_FACE', Buffer.from(JSON.stringify(state)));
  }

  // Helper: Add commitment to global list
  async _addCommitment(ctx, commitment, timestamp) {
    // Get current commitments
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    let store;
    
    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      store = { commitments: [], docType: 'commitments' };
    } else {
      store = JSON.parse(commitmentsBytes.toString());
    }

    // Check for duplicate commitment
    const isDuplicate = store.commitments.some(c => c.value === commitment);
    if (isDuplicate) {
      console.log('Commitment already registered, skipping duplicate');
      return;
    }

    // Add commitment
    store.commitments.push({
      value: commitment,
      registeredAt: timestamp
    });

    // Tree first: a lazy migration must read the list without this leaf
    await this._treeInsert(ctx, 'face', commitment);

    // Update store
    await ctx.stub.putState('GLOBAL_COMMITMENTS', Buffer.from(JSON.stringify(store)));
    
    console.log(`Added commitment. Total commitments: ${store.commitments.length}`);
  }

  // Get all registered commitments (for building Merkle tree client-side)
  async getCommitments(ctx) {
    console.log('============= START : Get Commitments ===========');
    
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    
    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return JSON.stringify([]);
    }

    const store = JSON.parse(commitmentsBytes.toString());
    
    console.log(`Commitments count: ${store.commitments.length}`);
    console.log('============= END : Get Commitments ===========');

    // Return only the commitment values
    return JSON.stringify(store.commitments.map(c => c.value));
  }

  // Get voter count (number of registered commitments)
  async getVoterCount(ctx) {
    console.log('============= START : Get Voter Count ===========');
    
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    
    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return 0;
    }

    const store = JSON.parse(commitmentsBytes.toString());
    
    console.log(`Voter count: ${store.commitments.length}`);
    console.log('============= END : Get Voter Count ===========');
    
    return store.commitments.length;
  }

  // ============================
  // IRIS REGISTRATION FUNCTIONS
  // (Independent Merkle tree)
  // ============================

  // Register a new voter via iris biometric
  async registerIris(ctx, nidHash, commitment) {
    console.log('============= START : Register Iris Identity ===========');
    this._assertRegistrar(ctx);

    if (!nidHash || !commitment) {
      throw new Error('All parameters (nidHash, commitment) are required');
    }

    // Check if already registered with iris (separate key space)
    const irisKey = `IRIS_${nidHash}`;
    const exists = await ctx.stub.getState(irisKey);
    if (exists && exists.length > 0) {
      throw new Error(`Iris identity with NID hash ${nidHash} is already registered`);
    }

    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    const identity = {
      nidHash,
      commitment,
      biometricType: 'iris',
      registeredAt: timestampStr,
      docType: 'iris_identity'
    };

    // Store per-user iris identity
    await ctx.stub.putState(irisKey, Buffer.from(JSON.stringify(identity)));

    // Add commitment to the independent iris commitments list
    await this._addIrisCommitment(ctx, commitment, timestampStr);

    // Emit registration event
    const eventPayload = {
      nidHash,
      commitment,
      biometricType: 'iris',
      timestamp: timestampStr
    };
    await ctx.stub.setEvent('IrisRegistered', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Iris identity registered: ${nidHash}`);
    console.log(`Iris commitment: ${commitment.slice(0, 20)}...`);
    console.log('============= END : Register Iris Identity ===========');

    return JSON.stringify(identity);
  }

  // Helper: Add commitment to global iris list
  async _addIrisCommitment(ctx, commitment, timestamp) {
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_IRIS_COMMITMENTS');
    let store;

    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      store = { commitments: [], docType: 'iris_commitments' };
    } else {
      store = JSON.parse(commitmentsBytes.toString());
    }

    const isDuplicate = store.commitments.some(c => c.value === commitment);
    if (isDuplicate) {
      console.log('Iris commitment already registered, skipping duplicate');
      return;
    }

    store.commitments.push({
      value: commitment,
      registeredAt: timestamp
    });

    // Tree first: a lazy migration must read the list without this leaf
    await this._treeInsert(ctx, 'iris', commitment);

    await ctx.stub.putState('GLOBAL_IRIS_COMMITMENTS', Buffer.from(JSON.stringify(store)));
    console.log(`Added iris commitment. Total iris commitments: ${store.commitments.length}`);
  }

  // Get all registered iris commitments (for building Merkle tree)
  async getIrisCommitments(ctx) {
    console.log('============= START : Get Iris Commitments ===========');

    const commitmentsBytes = await ctx.stub.getState('GLOBAL_IRIS_COMMITMENTS');

    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return JSON.stringify([]);
    }

    const store = JSON.parse(commitmentsBytes.toString());

    console.log(`Iris commitments count: ${store.commitments.length}`);
    console.log('============= END : Get Iris Commitments ===========');

    return JSON.stringify(store.commitments.map(c => c.value));
  }

  // Get iris voter count
  async getIrisVoterCount(ctx) {
    console.log('============= START : Get Iris Voter Count ===========');

    const commitmentsBytes = await ctx.stub.getState('GLOBAL_IRIS_COMMITMENTS');

    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return 0;
    }

    const store = JSON.parse(commitmentsBytes.toString());

    console.log(`Iris voter count: ${store.commitments.length}`);
    console.log('============= END : Get Iris Voter Count ===========');

    return store.commitments.length;
  }

  // ============================
  // SENSOR REGISTRY
  // Capture devices whose EdDSA-BabyJubJub key may attest live biometric
  // samples. Proofs reveal only the registry root, not which device.
  // ============================

  async registerSensor(ctx, ax, ay) {
    this._assertRegistrar(ctx);
    if (!/^[0-9]{1,78}$/.test(String(ax)) || !/^[0-9]{1,78}$/.test(String(ay))) {
      throw new Error('Sensor public key coordinates must be decimal field elements');
    }
    const bytes = await ctx.stub.getState('GLOBAL_SENSORS');
    const store = bytes && bytes.length > 0 ? JSON.parse(bytes.toString()) : { sensors: [], docType: 'sensors' };
    if (store.sensors.some((s) => s.ax === String(ax) && s.ay === String(ay))) {
      throw new Error('Sensor already registered');
    }
    if (store.sensors.length >= 2 ** SENSOR_TREE_LEVELS) {
      throw new Error('Sensor registry is full');
    }
    store.sensors.push({ ax: String(ax), ay: String(ay) });
    await ctx.stub.putState('GLOBAL_SENSORS', Buffer.from(JSON.stringify(store)));
    return JSON.stringify({ index: store.sensors.length - 1, root: (await this._sensorRoot(store)).toString() });
  }

  async _verifyEnrollment(ctx, nidHash, commitment, enrollProofJSON, enrollSignalsJSON) {
    const proof = JSON.parse(enrollProofJSON);
    const signals = JSON.parse(enrollSignalsJSON).map(String);
    if (signals.length !== ENROLL_PS.LENGTH) {
      throw new Error(`Enrollment proof must carry ${ENROLL_PS.LENGTH} public signals`);
    }
    if (signals[ENROLL_PS.COMMITMENT] !== String(commitment)) {
      throw new Error('Enrollment proof is for a different commitment');
    }
    if (signals[ENROLL_PS.NID_FIELD] !== ballotCrypto.nidFieldFor(nidHash).toString()) {
      throw new Error('Enrollment capture was attested for a different NID');
    }
    const bytes = await ctx.stub.getState('GLOBAL_SENSORS');
    const store = bytes && bytes.length > 0 ? JSON.parse(bytes.toString()) : { sensors: [] };
    if (signals[ENROLL_PS.SENSOR_ROOT] !== (await this._sensorRoot(store)).toString()) {
      throw new Error('Enrollment capture device is not in the registry');
    }
    if (!(await snarkjs.groth16.verify(enrollVKey, signals, proof))) {
      throw new Error('Enrollment proof is invalid');
    }
  }

  async getSensors(ctx) {
    const bytes = await ctx.stub.getState('GLOBAL_SENSORS');
    const store = bytes && bytes.length > 0 ? JSON.parse(bytes.toString()) : { sensors: [] };
    return JSON.stringify(store.sensors);
  }

  async _sensorRoot(store) {
    const leaves = [];
    for (const s of store.sensors) leaves.push((await poseidonHash2(BigInt(s.ax), BigInt(s.ay))).toString());
    return this.buildMerkleTreeOnChain(leaves, SENSOR_TREE_LEVELS);
  }

  // ============================
  // BALLOT FUNCTIONS
  // ============================

  // Register a ballot, its option count and its trustee set (t-of-n).
  // Nobody supplies the election key: the trustees post DKG dealings
  // (submitDealing), may disqualify a dealer whose private share is
  // inconsistent (complain), and finalizeBallotKey derives h = Σ A_i0 from
  // the qualified dealings (tallyCrypto.js). Write-once.
  // Lifecycle: keygen → open (castVote) → closed (publishTally).
  async registerBallot(ctx, ballotId, numOptions, trusteesJSON, threshold) {
    this._assertRegistrar(ctx);
    if (!ballotId || !numOptions || !trusteesJSON || !threshold) {
      throw new Error('Required parameters: ballotId, numOptions, trustees, threshold');
    }
    const key = `BALLOT_${ballotId}`;
    const existing = await ctx.stub.getState(key);
    if (existing && existing.length > 0) {
      throw new Error(`Ballot ${ballotId} is already registered`);
    }
    const n = parseInt(numOptions, 10);
    if (!Number.isInteger(n) || n < 2) {
      throw new Error('numOptions must be an integer >= 2');
    }
    const trustees = JSON.parse(trusteesJSON);
    const t = parseInt(threshold, 10);
    if (!Array.isArray(trustees) || trustees.length < 2 || trustees.length > tallyCrypto.MAX_TRUSTEES ||
        new Set(trustees).size !== trustees.length) {
      throw new Error(`trustees must be 2..${tallyCrypto.MAX_TRUSTEES} distinct public keys`);
    }
    for (const pk of trustees) tallyCrypto.ec.keyFromPublic(pk, 'hex').validate();
    if (!Number.isInteger(t) || t < 2 || t > trustees.length) {
      throw new Error('threshold must be an integer in [2, number of trustees]');
    }
    const record = {
      ballotId,
      numOptions: n,
      trustees,
      threshold: t,
      dealings: {},
      disqualified: [],
      publicKey: null,
      status: 'keygen',
      electionId: ballotCrypto.electionIdFor(ballotId).toString(),
      docType: 'ballot',
    };
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));
    return JSON.stringify(record);
  }

  async getBallot(ctx, ballotId) {
    const bytes = await ctx.stub.getState(`BALLOT_${ballotId}`);
    if (!bytes || bytes.length === 0) {
      throw new Error(`Ballot ${ballotId} is not registered on-chain`);
    }
    return bytes.toString();
  }

  async _ballotInState(ctx, ballotId, status) {
    const ballot = JSON.parse(await this.getBallot(ctx, ballotId));
    if (ballot.status !== status) {
      throw new Error(`Ballot ${ballotId} is ${ballot.status}, expected ${status}`);
    }
    return ballot;
  }

  _trusteeIndex(ballot, idx) {
    const i = parseInt(idx, 10);
    if (!Number.isInteger(i) || i < 1 || i > ballot.trustees.length) {
      throw new Error(`Trustee index must be in 1..${ballot.trustees.length}`);
    }
    return i;
  }

  // Trustee `dealer` publishes Feldman commitments to its polynomial,
  // signed with its registered key.
  async submitDealing(ctx, ballotId, dealer, commitmentsJSON, sig) {
    const ballot = await this._ballotInState(ctx, ballotId, 'keygen');
    const i = this._trusteeIndex(ballot, dealer);
    if (ballot.dealings[i]) throw new Error(`Trustee ${i} has already posted a dealing`);
    const commitments = JSON.parse(commitmentsJSON);
    if (!Array.isArray(commitments) || commitments.length !== ballot.threshold) {
      throw new Error(`A dealing must commit to exactly ${ballot.threshold} coefficients`);
    }
    commitments.forEach((c) => tallyCrypto.toPoint(c));
    if (!tallyCrypto.verifyTrusteeSig(ballot.trustees[i - 1], 'bbzkv-dealing-v1',
      { ballotId, dealer: i, commitments }, sig)) {
      throw new Error(`Dealing is not signed by trustee ${i}`);
    }
    ballot.dealings[i] = { dealer: i, commitments };
    await ctx.stub.putState(`BALLOT_${ballotId}`, Buffer.from(JSON.stringify(ballot)));
    return JSON.stringify({ dealer: i });
  }

  // Trustee `complainer` reveals the share it received from `dealer`. If the
  // share does not match the dealer's commitments, the dealer is disqualified;
  // a consistent share clears the dealer and the complaint fails.
  async complain(ctx, ballotId, complainer, dealer, shareHex, sig) {
    const ballot = await this._ballotInState(ctx, ballotId, 'keygen');
    const j = this._trusteeIndex(ballot, complainer);
    const i = this._trusteeIndex(ballot, dealer);
    if (i === j) throw new Error('A trustee cannot complain about itself');
    if (!ballot.dealings[i]) throw new Error(`Trustee ${i} has posted no dealing`);
    if (!tallyCrypto.verifyTrusteeSig(ballot.trustees[j - 1], 'bbzkv-complaint-v1',
      { ballotId, complainer: j, dealer: i, share: shareHex }, sig)) {
      throw new Error(`Complaint is not signed by trustee ${j}`);
    }
    if (tallyCrypto.verifyShare(ballot.dealings[i].commitments, j, shareHex)) {
      throw new Error(`Complaint rejected: trustee ${i}'s share to trustee ${j} is consistent`);
    }
    if (!ballot.disqualified.includes(i)) ballot.disqualified.push(i);
    await ctx.stub.putState(`BALLOT_${ballotId}`, Buffer.from(JSON.stringify(ballot)));
    return JSON.stringify({ disqualified: ballot.disqualified });
  }

  // Derive the election key from the qualified dealings and open voting.
  async finalizeBallotKey(ctx, ballotId) {
    const ballot = await this._ballotInState(ctx, ballotId, 'keygen');
    const n = ballot.trustees.length;
    if (Object.keys(ballot.dealings).length !== n) {
      throw new Error(`Only ${Object.keys(ballot.dealings).length} of ${n} trustees have posted dealings`);
    }
    const qual = Object.values(ballot.dealings).filter((d) => !ballot.disqualified.includes(d.dealer));
    // With at most t-1 corrupt trustees, |QUAL| >= t guarantees an honest dealer
    if (qual.length < ballot.threshold) {
      throw new Error(`Only ${qual.length} qualified dealings, threshold is ${ballot.threshold}`);
    }
    ballot.publicKey = tallyCrypto.ser(tallyCrypto.electionKey(qual));
    ballot.qual = qual.map((d) => d.dealer);
    ballot.status = 'open';
    await ctx.stub.putState(`BALLOT_${ballotId}`, Buffer.from(JSON.stringify(ballot)));
    return JSON.stringify({ publicKey: ballot.publicKey, qual: ballot.qual });
  }

  async closeBallot(ctx, ballotId) {
    this._assertRegistrar(ctx);
    const ballot = await this._ballotInState(ctx, ballotId, 'open');
    ballot.status = 'closed';
    await ctx.stub.putState(`BALLOT_${ballotId}`, Buffer.from(JSON.stringify(ballot)));
    return JSON.stringify({ status: 'closed' });
  }

  // Publish the result. The chaincode recomputes every aggregate from the
  // stored ballots and accepts the totals only with at least t valid partial
  // decryptions per option that open the aggregate to exactly that total.
  // Write-once. tally = { options: [{ total, partials: [{trustee, D, proof}] }] }
  async publishTally(ctx, ballotId, tallyJSON) {
    const ballot = await this._ballotInState(ctx, ballotId, 'closed');
    const tallyKey = `TALLY_${ballotId}`;
    const existing = await ctx.stub.getState(tallyKey);
    if (existing && existing.length > 0) throw new Error(`Tally for ${ballotId} is already published`);
    const tally = JSON.parse(tallyJSON);
    if (!tally || !Array.isArray(tally.options) || tally.options.length !== ballot.numOptions) {
      throw new Error(`Tally must have one entry per option (${ballot.numOptions})`);
    }
    const votes = JSON.parse(await this.getAllVotes(ctx, ballotId));
    const aggregates = Array.from({ length: ballot.numOptions }, () => null);
    for (const v of votes) {
      v.encryptedVote.ciphertexts.forEach((ct, j) => {
        const c = { c1: tallyCrypto.toPoint(ct.c1), c2: tallyCrypto.toPoint(ct.c2) };
        aggregates[j] = aggregates[j] ? { c1: aggregates[j].c1.add(c.c1), c2: aggregates[j].c2.add(c.c2) } : c;
      });
    }
    const key = {
      threshold: ballot.threshold,
      trustees: ballot.trustees.length,
      qualDealings: ballot.qual.map((i) => ballot.dealings[i]),
    };
    tally.options.forEach((entry, j) => {
      if (votes.length === 0) {
        if (entry.total !== 0) throw new Error(`Option ${j}: no ballots, total must be 0`);
        return;
      }
      tallyCrypto.verifyOptionTally(key, aggregates[j], j, ballotId, entry);
    });
    const record = {
      ballotId,
      numVotes: votes.length,
      totals: tally.options.map((e) => e.total),
      options: tally.options,
      docType: 'tally',
    };
    await ctx.stub.putState(tallyKey, Buffer.from(JSON.stringify(record)));
    return JSON.stringify({ ballotId, numVotes: record.numVotes, totals: record.totals });
  }

  async getTally(ctx, ballotId) {
    const bytes = await ctx.stub.getState(`TALLY_${ballotId}`);
    if (!bytes || bytes.length === 0) {
      throw new Error(`No tally published for ${ballotId}`);
    }
    return bytes.toString();
  }

  // ============================
  // VOTING FUNCTIONS
  // ============================

  // -------------------------------------------------------
  // Helper: Verify a ZK-SNARK Groth16 proof on-chain
  // Selects the correct verification key based on biometricType.
  // Public signal layout: see PS at the top of this file.
  // -------------------------------------------------------
  async verifyZkProof(proof, publicSignals, biometricType) {
    const vkey = biometricType === 'iris' ? irisVKey : faceVKey;

    console.log(`🔐 On-chain Groth16 verification (${biometricType})...`);
    const startTime = Date.now();

    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

    const elapsed = Date.now() - startTime;
    console.log(`   Groth16 result: ${isValid} (${elapsed}ms)`);

    return isValid;
  }

  // Cast a vote with ZK-SNARK proof + nullifier
  // The chaincode performs FULL on-chain verification:
  //   1. snarkjs.groth16.verify() — cryptographic soundness
  //   2. Output validity — circuit output signal must be 1
  //   3. Nullifier consistency — proof nullifier matches submitted nullifier
  //   4. Merkle root validation — voter is a registered member
  //   5. Election binding — proof electionId is derived from this ballotId
  //      (+ sensor attestation — proof sensorRoot is the current device registry)
  //   6. Ballot binding — proof voteBinding commits to these ciphertexts
  //   7. Ballot well-formedness — every entry encrypts 0/1 and they sum to 1
  //   8. Double-vote check — nullifier unused
  // The chaincode is completely oblivious to the voter's identity.
  // The nullifier prevents double voting without revealing who voted.
  async castVote(ctx, proofJSON, publicSignalsJSON, nullifier, encryptedVoteJSON, ballotId, biometricType) {
    console.log('============= START : Cast Vote (On-Chain Verification) ===========');

    if (!proofJSON || !publicSignalsJSON || !nullifier || !ballotId || !encryptedVoteJSON) {
      throw new Error('Required parameters: proof, publicSignals, nullifier, encryptedVote, ballotId');
    }

    const proof = JSON.parse(proofJSON);
    const publicSignals = JSON.parse(publicSignalsJSON);
    const bioType = biometricType || 'face';
    if (bioType !== 'face' && bioType !== 'iris') {
      throw new Error(`Unknown biometricType: ${bioType}`);
    }
    if (!Array.isArray(publicSignals) || publicSignals.length !== PS.LENGTH) {
      throw new Error(`Expected ${PS.LENGTH} public signals, got ${publicSignals && publicSignals.length}`);
    }

    // The ballot must be registered on-chain (fixes its key and option count),
    // its key generated by the trustees, and voting not yet closed
    const ballot = JSON.parse(await this.getBallot(ctx, ballotId));
    if (ballot.status !== 'open') {
      throw new Error(`Ballot ${ballotId} is not open for voting (status: ${ballot.status})`);
    }

    // =====================================================
    // STEP 1: Groth16 cryptographic proof verification
    // =====================================================
    const proofValid = await this.verifyZkProof(proof, publicSignals, bioType);
    if (!proofValid) {
      throw new Error('ZK-SNARK proof verification FAILED — invalid proof');
    }
    console.log('✅ Groth16 proof verified on-chain');

    // =====================================================
    // STEP 2: Validate circuit output
    //   The circuit output "valid" must be 1, meaning
    //   the biometric check (cosine/Hamming) passed.
    // =====================================================
    if (publicSignals[PS.VALID] !== '1') {
      throw new Error('ZK-SNARK output invalid — biometric similarity check failed inside circuit');
    }
    console.log('✅ Circuit output valid = 1');

    // =====================================================
    // STEP 3: Nullifier consistency check
    // =====================================================
    if (publicSignals[PS.NULLIFIER] !== nullifier) {
      throw new Error('Nullifier mismatch — submitted nullifier does not match proof public signal');
    }
    console.log('✅ Nullifier matches proof');

    // =====================================================
    // STEP 4: Merkle root validation
    //   Compare with the root maintained incrementally at
    //   registration: O(1) per vote instead of rebuilding the
    //   tree from every commitment (O(N·L)).
    // =====================================================
    const tree = await this._treeState(ctx, bioType);
    if (tree.nextIndex === 0) {
      throw new Error('No registered commitments found on-chain');
    }
    const onChainRoot = BigInt(tree.root);
    const proofMerkleRoot = BigInt(publicSignals[PS.ROOT]);

    if (onChainRoot !== proofMerkleRoot) {
      throw new Error(
        `Merkle root mismatch — proof root ${proofMerkleRoot.toString().slice(0, 20)}... ` +
        `does not match on-chain root ${onChainRoot.toString().slice(0, 20)}...`
      );
    }
    console.log('✅ Merkle root verified against on-chain commitments');

    // =====================================================
    // STEP 5: Election binding
    //   Any other electionId yields a fresh nullifier for the
    //   same credential, i.e. unlimited votes on this ballot.
    // =====================================================
    if (publicSignals[PS.ELECTION_ID] !== ballot.electionId) {
      throw new Error('ElectionId in proof does not belong to this ballot');
    }
    console.log('✅ ElectionId bound to ballot');

    // =====================================================
    // STEP 5b: Sensor attestation
    //   The circuit verified an EdDSA signature by a key in the
    //   registry with this root; it must be the current registry.
    // =====================================================
    const sensorBytes = await ctx.stub.getState('GLOBAL_SENSORS');
    const sensorStore = sensorBytes && sensorBytes.length > 0 ? JSON.parse(sensorBytes.toString()) : { sensors: [] };
    if (sensorStore.sensors.length === 0) {
      throw new Error('No authorised capture devices registered');
    }
    if (publicSignals[PS.SENSOR_ROOT] !== (await this._sensorRoot(sensorStore)).toString()) {
      throw new Error('Sensor registry root mismatch — live sample not attested by an authorised capture device');
    }
    console.log('✅ Live sample attested by an authorised capture device');

    // =====================================================
    // STEP 6 + 7: Ballot binding and well-formedness
    // =====================================================
    let encryptedVote;
    try {
      encryptedVote = JSON.parse(encryptedVoteJSON);
    } catch (err) {
      throw new Error('Encrypted vote is not valid JSON');
    }
    const binding = ballotCrypto.computeVoteBinding(ballotId, encryptedVote);
    if (publicSignals[PS.VOTE_BINDING] !== binding.toString()) {
      throw new Error('Vote binding mismatch — ciphertexts are not the ones this proof was made for');
    }
    ballotCrypto.verifyEncryptedBallot(ballot.publicKey, ballot.numOptions, encryptedVote, ballotId, nullifier);
    console.log('✅ Ciphertexts bound to proof and well-formed (0/1 each, sum = 1)');

    // =====================================================
    // STEP 8: Double-vote check via nullifier
    // =====================================================
    const nullifierKey = `NULLIFIER_${nullifier}`;
    const existingVote = await ctx.stub.getState(nullifierKey);

    if (existingVote && existingVote.length > 0) {
      throw new Error('Double voting detected - this identity has already voted');
    }

    // Use txId as the unique, conflict-free vote identifier
    const txId = ctx.stub.getTxID();
    const voteId = `VOTE_${txId}`;

    // Get timestamp
    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    // Create vote record — proof is stored for public auditability
    const vote = {
      voteId,
      ballotId: ballotId || '',
      proof,
      publicSignals,
      nullifier,
      biometricType: bioType,
      encryptedVote,
      onChainVerified: true,
      timestamp: timestampStr,
      txId,
      docType: 'vote'
    };

    // Store vote — key is unique per transaction, zero read-write conflict
    await ctx.stub.putState(voteId, Buffer.from(JSON.stringify(vote)));

    // Store nullifier to prevent double voting
    const nullifierRecord = {
      voteId,
      timestamp: timestampStr,
      docType: 'nullifier'
    };
    await ctx.stub.putState(nullifierKey, Buffer.from(JSON.stringify(nullifierRecord)));

    // Emit vote event (without revealing identity or choice)
    const eventPayload = {
      voteId,
      ballotId: ballotId || '',
      biometricType: bioType,
      hasEncryption: encryptedVote !== null,
      onChainVerified: true,
      timestamp: timestampStr
    };
    
    await ctx.stub.setEvent('VoteCast', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Vote cast: ${voteId}`);
    console.log(`Ballot: ${ballotId || 'not specified'}`);
    console.log(`Biometric: ${bioType}`);
    console.log(`Nullifier: ${nullifier.slice(0, 20)}...`);
    console.log(`On-chain verified: true`);
    console.log(`Encrypted: ${encryptedVote !== null}`);
    console.log('============= END : Cast Vote (On-Chain Verification) ===========');

    return JSON.stringify({
      voteId,
      ballotId: ballotId || '',
      onChainVerified: true,
      timestamp: timestampStr
    });
  }

  // Check if a nullifier has been used (double-vote check)
  async hasVoted(ctx, nullifier) {
    console.log('============= START : Check Has Voted ===========');
    
    const nullifierKey = `NULLIFIER_${nullifier}`;
    const existingVote = await ctx.stub.getState(nullifierKey);
    
    const hasVoted = existingVote && existingVote.length > 0;
    
    console.log(`Nullifier used: ${hasVoted}`);
    console.log('============= END : Check Has Voted ===========');
    
    return hasVoted;
  }

  // Get vote results (tally)
  async getVoteResults(ctx, ballotId = '') {
    console.log('============= START : Get Vote Results ===========');
    
    let totalVotes = 0;

    const queryString = {
      selector: {
        docType: 'vote'
      }
    };
    
    if (ballotId && ballotId.trim() !== '') {
      queryString.selector.ballotId = ballotId;
    }

    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'vote') {
          totalVotes++;
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();

    // Get voter count
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    let voterCount = 0;
    
    if (commitmentsBytes && commitmentsBytes.length > 0) {
      const store = JSON.parse(commitmentsBytes.toString());
      voterCount = store.commitments.length;
    }

    console.log(`Total votes: ${totalVotes}`);
    console.log(`Voter count: ${voterCount}`);
    console.log('============= END : Get Vote Results ===========');
    
    return JSON.stringify({
      totalVotes,
      tallies: {},
      voterCount
    });
  }

  // Get a specific vote (for verification)
  async getVote(ctx, voteId) {
    console.log('============= START : Get Vote ===========');
    
    if (!voteId) {
      throw new Error('Vote ID is required');
    }

    const voteBytes = await ctx.stub.getState(voteId);
    
    if (!voteBytes || voteBytes.length === 0) {
      throw new Error(`Vote ${voteId} does not exist`);
    }

    const vote = JSON.parse(voteBytes.toString());
    
    console.log('============= END : Get Vote ===========');
    
    return JSON.stringify(vote);
  }

  // Get vote count
  async getVoteCount(ctx, ballotId = '') {
    console.log('============= START : Get Vote Count ===========');

    let count = 0;
    
    const queryString = {
      selector: {
        docType: 'vote'
      }
    };
    
    if (ballotId && ballotId.trim() !== '') {
      queryString.selector.ballotId = ballotId;
    }

    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();
    
    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      try {
        const record = JSON.parse(strValue);
        if (record.docType === 'vote') count++;
      } catch (_) {}
      result = await iterator.next();
    }
    await iterator.close();

    console.log(`Total votes: ${count}`);
    console.log('============= END : Get Vote Count ===========');

    return count;
  }

  // Get all votes (for auditing)
  async getAllVotes(ctx, ballotId = '') {
    console.log('============= START : Get All Votes ===========');
    
    const allVotes = [];
    
    const queryString = {
      selector: {
        docType: 'vote'
      }
    };
    
    if (ballotId && ballotId.trim() !== '') {
      queryString.selector.ballotId = ballotId;
    }

    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'vote') {
          allVotes.push({
            voteId: record.voteId,
            ballotId: record.ballotId || '',
            nullifier: record.nullifier,
            timestamp: record.timestamp,
            encryptedVote: record.encryptedVote,
            proof: record.proof,
            publicSignals: record.publicSignals
          });
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();
    
    console.log(`Found ${allVotes.length} votes`);
    console.log(`Votes with encryption: ${allVotes.filter(v => v.encryptedVote !== null).length}`);
    console.log('============= END : Get All Votes ===========');
    
    return JSON.stringify(allVotes);
  }

  // ============================
  // LEGACY COMPATIBILITY
  // ============================

  // Get user data by nidHash (legacy)
  async getUserData(ctx, nidHash) {
    console.log('============= START : Get User Data ===========');
    
    if (!nidHash) {
      throw new Error('NID hash is required');
    }

    const identityBytes = await ctx.stub.getState(nidHash);
    
    if (!identityBytes || identityBytes.length === 0) {
      throw new Error(`Identity with NID hash ${nidHash} does not exist`);
    }

    const identity = JSON.parse(identityBytes.toString());
    
    console.log(`Retrieved identity: ${nidHash}`);
    console.log('============= END : Get User Data ===========');

    return JSON.stringify({
      commitment: identity.commitment
    });
  }

  // Get all registered identities (legacy)
  async getAllRegistered(ctx) {
    console.log('============= START : Get All Registered ===========');
    
    const allResults = [];
    
    const queryString = {
      selector: {
        docType: 'identity'
      }
    };
    
    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'identity') {
          allResults.push(record.nidHash);
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();
    
    console.log(`Found ${allResults.length} registered identities`);
    console.log('============= END : Get All Registered ===========');
    
    return JSON.stringify(allResults);
  }

  // Legacy: getRing → returns commitments
  async getRing(ctx) {
    return await this.getCommitments(ctx);
  }

  // Legacy: getRingSize → returns voter count
  async getRingSize(ctx) {
    return await this.getVoterCount(ctx);
  }
}

module.exports = IdentityContract;