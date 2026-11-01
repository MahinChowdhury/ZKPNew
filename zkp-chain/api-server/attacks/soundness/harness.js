// ============================================================
// harness.js — shared plumbing for the soundness attack suite
//
// Proves against the CURRENT circuit sources (compiled by
// build_test_artifacts.sh) and submits to the REAL chaincode
// IdentityContract through an in-memory Fabric stub. The only
// substitution is the verification key: the chaincode's
// require('./verification_key.json') is pointed at the test vkey,
// because production keys aren't in the repo.
// ============================================================

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");

const BUILD = path.join(__dirname, "build");
const CHAINCODE_LIB = path.join(__dirname, "..", "..", "..", "chaincode", "identity", "lib");
const LEVELS = 20;
const SCALE = 500000;   // σ, matches FACE_SCALE and the circuit range check |x| < 2^19
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const mod = (a) => ((a % P) + P) % P;

function modInv(a) {
  // Fermat: a^(p-2) mod p
  let result = 1n, base = mod(a), e = P - 2n;
  while (e > 0n) {
    if (e & 1n) result = (result * base) % P;
    base = (base * base) % P;
    e >>= 1n;
  }
  return result;
}

const fieldStr = (v) => mod(BigInt(v)).toString();

// ------------------------------------------------------------
// Poseidon + sparse Merkle tree (mirrors snark.js / chaincode)
// ------------------------------------------------------------
let _poseidon;
async function H(...xs) {
  if (!_poseidon) _poseidon = await circomlibjs.buildPoseidon();
  return _poseidon.F.toObject(_poseidon(xs.map((x) => _poseidon.F.e(x))));
}

async function zeroHashes(levels = LEVELS) {
  const z = [0n];
  for (let i = 0; i < levels; i++) z.push(await H(z[i], z[i]));
  return z;
}

async function buildTree(leaves, levels = LEVELS) {
  const z = await zeroHashes(levels);
  const layers = [new Map(leaves.map((v, i) => [i, BigInt(v)]))];
  for (let lvl = 0; lvl < levels; lvl++) {
    const next = new Map();
    const parents = new Set([...layers[lvl].keys()].map((i) => Math.floor(i / 2)));
    for (const p of parents) {
      const l = layers[lvl].get(2 * p) ?? z[lvl];
      const r = layers[lvl].get(2 * p + 1) ?? z[lvl];
      next.set(p, await H(l, r));
    }
    layers.push(next);
  }
  const node = (lvl, idx) => layers[lvl].get(idx) ?? z[lvl];
  return { root: node(levels, 0), node, z, levels };
}

async function merklePath(tree, leafIndex) {
  const pathElements = [], pathIndices = [];
  let idx = leafIndex;
  for (let lvl = 0; lvl < tree.levels; lvl++) {
    pathElements.push(tree.node(lvl, idx ^ 1));
    pathIndices.push(idx & 1);
    idx >>= 1;
  }
  return { pathElements, pathIndices };
}

// ------------------------------------------------------------
// Biometric material
// ------------------------------------------------------------
function randomUnitEmbedding(dim = 128) {   // deployed face dimension (face_auth.circom)
  const v = Array.from({ length: dim }, () => {
    // Box–Muller
    const u = 1 - Math.random(), w = Math.random();
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * w);
  });
  const n = Math.hypot(...v);
  return v.map((x) => BigInt(Math.round((x / n) * SCALE)));
}

function noisyCopy(emb, sigma = 0.15) {
  const f = emb.map((x) => Number(x) / SCALE + sigma * (Math.random() * 2 - 1) / 8);
  const n = Math.hypot(...f);
  return f.map((x) => BigInt(Math.round((x / n) * SCALE)));
}

const randomBits = (n = 256) => Array.from({ length: n }, () => (Math.random() < 0.5 ? 1 : 0));

// Mirrors PackedCoordHash(d, 19): offset coordinates x + 2^19 in 20-bit slots,
// 12 per field element. Packs whatever it is given (no range check), so an
// attack can compute the digest of an out-of-range template.
function packCoords(emb) {
  const packed = [];
  for (let e = 0; e * 12 < emb.length; e++) {
    let v = 0n;
    for (let j = 0; j < 12 && e * 12 + j < emb.length; j++) v += (BigInt(emb[e * 12 + j]) + (1n << 19n)) << (20n * BigInt(j));
    packed.push(mod(v));
  }
  return packed;
}

async function faceDigestOf(emb) {
  const packed = packCoords(emb);
  if (packed.length <= 16) return H(...packed);
  const groups = [];
  for (let q = 0; q < packed.length; q += 16) groups.push(await H(...packed.slice(q, q + 16)));
  return H(...groups);
}

async function faceHashOf(emb, salt) {
  return H(await faceDigestOf(emb), salt);
}

async function irisHashOf(bits, salt) {
  const packed = [];
  for (let i = 0; i < 32; i++) {
    let v = 0n;
    for (let j = 0; j < 8; j++) v += BigInt(bits[i * 8 + j]) << BigInt(j);
    packed.push(v);
  }
  const chunks = [];
  for (let i = 0; i < 4; i++) chunks.push(await H(...packed.slice(i * 8, i * 8 + 8)));
  return H(await H(...chunks), salt);
}

function randomSecret() {
  return BigInt("0x" + crypto.randomBytes(31).toString("hex")) || 1n;
}

// Mirrors routes/vote.js: electionId = first 128 bits of SHA256(ballotId)
function electionIdFor(ballotId) {
  return BigInt("0x" + crypto.createHash("sha256").update(String(ballotId)).digest("hex").slice(0, 32));
}

async function makeFaceVoter() {
  const template = randomUnitEmbedding();
  const salt = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
  const sk = randomSecret();
  const faceHash = await faceHashOf(template, salt);
  return { kind: "face", template, salt, sk, bioHash: faceHash, commitment: await H(faceHash, sk) };
}

async function makeIrisVoter() {
  const template = randomBits();
  const salt = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
  const sk = randomSecret();
  const irisHash = await irisHashOf(template, salt);
  return { kind: "iris", template, salt, sk, bioHash: irisHash, commitment: await H(irisHash, sk) };
}

// ------------------------------------------------------------
// Proving. Witness generation enforces every === / <== constraint,
// so an unsatisfiable witness throws here — that counts as PROTECTED.
// ------------------------------------------------------------
async function prove(circuit, input) {
  const wasm = path.join(BUILD, `${circuit}_js`, `${circuit}.wasm`);
  const zkey = path.join(BUILD, `${circuit}.zkey`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  const vkey = JSON.parse(fs.readFileSync(path.join(BUILD, `${circuit}_vkey.json`)));
  if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
    throw new Error("proof generated but failed verification");
  }
  return { proof, publicSignals };
}

function faceInput(v, { live, registered, electionId, root, path: mp, voteBinding }) {
  return {
    merkleRoot: fieldStr(root),
    nullifier: "0", // overwritten below
    electionId: fieldStr(electionId),
    voteBinding: fieldStr(voteBinding),
    embedding: live.map(fieldStr),
    registeredEmbedding: (registered ?? v.template).map(fieldStr),
    salt: fieldStr(v.salt),
    secretKey: fieldStr(v.sk),
    pathElements: mp.pathElements.map(fieldStr),
    pathIndices: mp.pathIndices.map(fieldStr),
  };
}

function irisInput(v, { live, electionId, root, path: mp, voteBinding }) {
  return {
    merkleRoot: fieldStr(root),
    nullifier: "0",
    electionId: fieldStr(electionId),
    voteBinding: fieldStr(voteBinding),
    irisCodeLive: live.map(String),
    irisCodeRegistered: v.template.map(String),
    salt: fieldStr(v.salt),
    secretKey: fieldStr(v.sk),
    pathElements: mp.pathElements.map(fieldStr),
    pathIndices: mp.pathIndices.map(fieldStr),
  };
}

// ------------------------------------------------------------
// Capture-device attestation (sensor/attest-core.js signs; the voter
// client's templateDigest/attestationMessage define the message)
// ------------------------------------------------------------
const SENSOR_LEVELS = 10;
let _client;
const voterClient = async () => (_client ??= await import(path.join(__dirname, "..", "..", "..", "frontend", "src", "crypto", "voterClient.js")));

/**
 * Witness fields for SensorAttestation. `s` describes the capture:
 *   signer, tree, index        — signing key and its slot in the registry tree
 *   signedTemplate             — what the device actually captured (default: the live template)
 *   signElectionId, signNullifier — what the signature was bound to (default: this vote)
 *   claimKey                   — key placed in the witness (default: signer's)
 */
async function sensorFields(kind, live, electionId, nullifier, s) {
  const client = await voterClient();
  // Face: the harness's own packer, so an out-of-range sample (A5b) reaches the
  // circuit's range checks instead of being refused by the client.
  const signed = s.signedTemplate ?? live;
  const digest = kind === "face" ? await faceDigestOf(signed) : await client.templateDigest(kind, signed);
  const sessionNonce = randomSecret();
  const sessionCommit = await H(s.signNullifier ?? nullifier, sessionNonce);
  const sig = s.signer.sign(await H(digest, s.signElectionId ?? electionId, sessionCommit));
  const key = s.claimKey ?? s.signer.publicKey;
  const p = await merklePath(s.tree, s.index);
  return {
    sensorRoot: fieldStr(s.tree.root),
    sessionNonce: fieldStr(sessionNonce),
    sensorAx: key.ax, sensorAy: key.ay,
    sigR8x: sig.R8x, sigR8y: sig.R8y, sigS: sig.S,
    sensorPathElements: p.pathElements.map(fieldStr),
    sensorPathIndices: p.pathIndices.map(fieldStr),
  };
}

// opts.sensor: capture attestation (see sensorFields).
// opts.extra: additional witness inputs an attacker tries to inject (e.g. a
// threshold). If the circuit has no such signal, witness generation ignores
// it and the real constraints decide.
async function proveVote(v, opts) {
  const circuit = v.kind === "face" ? "face_auth" : "iris_auth";
  const input = v.kind === "face" ? faceInput(v, opts) : irisInput(v, opts);
  const nullifier = await nullifierOf(v, opts.electionId);
  input.nullifier = fieldStr(nullifier);
  Object.assign(input, await sensorFields(v.kind, opts.live, opts.electionId, nullifier, opts.sensor));
  Object.assign(input, opts.extra || {});
  const { proof, publicSignals } = await prove(circuit, input);
  return { proof, publicSignals, nullifier: input.nullifier };
}

const nullifierOf = (v, electionId) => H(v.sk, electionId);

// ------------------------------------------------------------
// Attested enrollment (enroll_auth.circom). The kiosk signs
// Poseidon(digest, domain, Poseidon(nidField(nid), 0)); `domain` defaults to
// the enrollment domain, an attacker may substitute an electionId (A26).
// Returns the extra register() arguments [proofJSON, signalsJSON].
// ------------------------------------------------------------
const ENROLL_DOMAIN = 1n << 200n;
const nidFieldOf = (nid) => BigInt("0x" + crypto.createHash("sha256").update(String(nid)).digest("hex").slice(0, 62));

async function enrollmentProof(v, nid, sensor, { domain = ENROLL_DOMAIN } = {}) {
  const nidField = nidFieldOf(nid);
  const msg = await H(await faceDigestOf(v.template), domain, await H(nidField, 0n));
  const sig = sensor.signer.sign(msg);
  const p = await merklePath(sensor.tree, sensor.index);
  const input = {
    commitment: fieldStr(v.commitment),
    nidField: fieldStr(nidField),
    sensorRoot: fieldStr(sensor.tree.root),
    enrolled: v.template.map(fieldStr),
    salt: fieldStr(v.salt),
    secretKey: fieldStr(v.sk),
    sensorAx: sensor.signer.publicKey.ax, sensorAy: sensor.signer.publicKey.ay,
    sigR8x: sig.R8x, sigR8y: sig.R8y, sigS: sig.S,
    sensorPathElements: p.pathElements.map(fieldStr),
    sensorPathIndices: p.pathIndices.map(fieldStr),
  };
  const { proof, publicSignals } = await prove("enroll_auth", input);
  return [JSON.stringify(proof), JSON.stringify(publicSignals)];
}

// RA enrollment of a face voter through the attested path
async function registerFace(contract, ctx, nid, v, sensor) {
  return quiet(async () => contract.register(ctx, nid, v.commitment.toString(), ...(await enrollmentProof(v, nid, sensor))));
}

// ------------------------------------------------------------
// Chaincode under an in-memory Fabric stub
// ------------------------------------------------------------
function loadContract() {
  for (const [file, circuit] of [["verification_key.json", "face_auth"], ["iris_verification_key.json", "iris_auth"],
                                  ["enroll_verification_key.json", "enroll_auth"]]) {
    const resolved = path.join(CHAINCODE_LIB, file);
    require.cache[resolved] = {
      id: resolved, filename: resolved, loaded: true,
      exports: JSON.parse(fs.readFileSync(path.join(BUILD, `${circuit}_vkey.json`))),
    };
  }
  const IdentityContract = require(path.join(CHAINCODE_LIB, "identityContract.js"));
  return new IdentityContract();
}

function makeLedger(mspId = "Org1MSP") {
  const state = new Map();
  let tx = 0;
  return {
    state,
    ctx: {
      stub: {
        getState: async (k) => state.get(k) ?? Buffer.alloc(0),
        putState: async (k, v) => { state.set(k, Buffer.from(v)); },
        getTxID: () => `tx${++tx}`,
        getTxTimestamp: () => ({ seconds: { low: Math.floor(Date.now() / 1000) } }),
        setEvent: () => {},
        // CouchDB rich query, equality selectors only (all the chaincode uses)
        getQueryResult: async (queryJSON) => {
          const { selector } = JSON.parse(queryJSON);
          const rows = [];
          for (const [key, buf] of state) {
            let doc;
            try { doc = JSON.parse(buf.toString()); } catch { continue; }
            if (Object.entries(selector).every(([f, v]) => doc[f] === v)) rows.push({ key, value: buf });
          }
          let i = 0;
          return {
            next: async () => (i < rows.length ? { value: rows[i++], done: false } : { done: true }),
            close: async () => {},
          };
        },
      },
      clientIdentity: { getMSPID: () => mspId, getID: () => `x509::CN=${mspId}-user` },
    },
  };
}

// Run fn with chaincode console chatter suppressed
async function quiet(fn) {
  const log = console.log, warn = console.warn;
  console.log = console.warn = () => {};
  try { return await fn(); } finally { console.log = log; console.warn = warn; }
}

// ------------------------------------------------------------
// Ballot with a t-of-n trustee key, generated through the chaincode:
// registerBallot → submitDealing (n) → complaints → finalizeBallotKey.
// opts.corrupt(dealer, receiver, share) may return a replacement share,
// to model a dealer that sends someone an inconsistent share.
// ------------------------------------------------------------
async function setupBallot(contract, ctx, ballotId, numOptions, { n = 3, t = 2, corrupt } = {}) {
  const { Trustee } = require("../../crypto/threshold");
  const trustees = Array.from({ length: n }, (_, i) => new Trustee(i + 1));
  await quiet(() => contract.registerBallot(ctx, ballotId, String(numOptions),
    JSON.stringify(trustees.map((x) => x.publicKey)), String(t)));
  const dealings = trustees.map((x) => x.deal(ballotId, t, n));
  for (const x of trustees) {
    const d = dealings[x.index - 1];
    await quiet(() => contract.submitDealing(ctx, ballotId, String(x.index), JSON.stringify(d.commitments), d.sig));
  }
  const complaints = [];
  for (const r of trustees) {
    for (const d of trustees) {
      let share = dealings[d.index - 1].shares[r.index];
      share = (corrupt && corrupt(d.index, r.index, share)) || share;
      const c = r.receive(ballotId, d.index, dealings[d.index - 1].commitments, share);
      if (c) {
        complaints.push(c);
        await quiet(() => contract.complain(ctx, ballotId, String(c.complainer), String(c.dealer), c.share, c.sig));
      }
    }
  }
  const { qual } = JSON.parse(await quiet(() => contract.finalizeBallotKey(ctx, ballotId)));
  trustees.forEach((x) => x.finalize(qual));
  const record = JSON.parse(await contract.getBallot(ctx, ballotId));
  return { trustees, record, qual, complaints, dealings };
}

module.exports = {
  P, LEVELS, SENSOR_LEVELS, SCALE, mod, modInv, fieldStr, H,
  zeroHashes, buildTree, merklePath,
  randomUnitEmbedding, noisyCopy, randomBits, faceDigestOf,
  makeFaceVoter, makeIrisVoter, electionIdFor,
  proveVote, nullifierOf, loadContract, makeLedger, quiet, setupBallot,
  enrollmentProof, registerFace, ENROLL_DOMAIN,
};
