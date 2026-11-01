// ============================
// Homomorphic Encryption
// Exponential ElGamal over secp256k1
// ============================

const crypto = require("crypto");
const EC = require("elliptic").ec;
const BN = require("bn.js");

const ec = new EC("secp256k1");

/**
 * Generate ElGamal keypair
 * @returns {{ privateKey: BN, publicKey: Point }}
 */
function generateKeypair() {
  // Private key: random scalar x
  const privateKey = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  if (privateKey.isZero()) throw new Error("Invalid private key");
  
  // Public key: h = x·G
  const publicKey = ec.g.mul(privateKey);
  
  return { privateKey, publicKey };
}

/**
 * Encode vote as point on curve
 * For vote index i, encode as v·G where v is the vote value
 * @param {number} voteValue - The vote value (0, 1, 2, ...)
 * @returns {Point} Encoded vote as point
 */
function encodeVote(voteValue) {
  if (voteValue < 0) throw new Error("Vote value must be non-negative");
  
  // Encode as v·G (exponential encoding)
  const v = new BN(voteValue);
  return ec.g.mul(v);
}

/**
 * Encrypt a vote using Exponential ElGamal
 * @param {Point} publicKey - ElGamal public key h
 * @param {number} voteValue - The vote value to encrypt
 * @returns {{ c1: Point, c2: Point, r: BN }} Ciphertext (c1, c2) and randomness r
 */
function encrypt(publicKey, voteValue) {
  // Random r ∈ [1, n-1]
  const r = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  if (r.isZero()) throw new Error("Invalid randomness");
  
  // Encode vote: M = v·G
  const M = encodeVote(voteValue);
  
  // c1 = r·G
  const c1 = ec.g.mul(r);
  
  // c2 = M + r·h = v·G + r·h
  const c2 = M.add(publicKey.mul(r));
  
  return { c1, c2, r };
}

/**
 * Homomorphic addition of two ciphertexts
 * @param {{ c1: Point, c2: Point }} cipher1 
 * @param {{ c1: Point, c2: Point }} cipher2 
 * @returns {{ c1: Point, c2: Point }} Sum of ciphertexts
 */
function addCiphertexts(cipher1, cipher2) {
  // Homomorphic property: E(m1) + E(m2) = E(m1 + m2)
  // (c1, c2) + (c1', c2') = (c1 + c1', c2 + c2')
  return {
    c1: cipher1.c1.add(cipher2.c1),
    c2: cipher1.c2.add(cipher2.c2)
  };
}

/**
 * Decrypt a ciphertext
 * @param {BN} privateKey - ElGamal private key x
 * @param {{ c1: Point, c2: Point }} ciphertext 
 * @returns {Point} Decrypted message M = v·G
 */
function decrypt(privateKey, ciphertext) {
  const { c1, c2 } = ciphertext;
  
  // M = c2 - x·c1 = (v·G + r·h) - x·(r·G) = v·G
  const M = c2.add(c1.mul(privateKey).neg());
  
  return M;
}

/**
 * Solve discrete log to recover vote count from M = v·G
 * Uses baby-step giant-step algorithm
 * @param {Point} M - The point M = v·G
 * @param {number} maxValue - Maximum expected value
 * @returns {number} The vote count v
 */
function solveDiscreteLog(M, maxValue = 10000) {
  console.log(`\n=== SOLVING DISCRETE LOG ===`);
  console.log(`Max value: ${maxValue}`);
  
  // Validate input
  if (!M || typeof M.getX !== 'function') {
    console.error('Invalid point M:', M);
    throw new Error('Invalid point provided to solveDiscreteLog');
  }

  // Check if M is point at infinity (represents 0)
  if (M.isInfinity()) {
    console.log('Point is at infinity → vote count = 0');
    return 0;
  }

  console.log(`Point M coordinates:`);
  console.log(`  x: ${M.getX().toString(16).slice(0, 32)}...`);
  console.log(`  y: ${M.getY().toString(16).slice(0, 32)}...`);

  // Baby-step giant-step algorithm
  const m = Math.ceil(Math.sqrt(maxValue));
  console.log(`Using baby-step giant-step with m = ${m}`);
  
  // Baby steps: compute table of j·G for j = 0, 1, ..., m-1
  const table = new Map();
  let point = ec.curve.point(null, null); // Point at infinity (identity)
  
  for (let j = 0; j < m; j++) {
    if (point.isInfinity()) {
      table.set("infinity", j);
    } else {
      const key = point.getX().toString(16);
      table.set(key, j);
    }
    point = point.add(ec.g);
  }
  
  console.log(`Baby steps complete: ${table.size} entries`);
  
  // Giant steps: compute M - i·m·G for i = 0, 1, 2, ...
  const mG = ec.g.mul(new BN(m));
  let current = M;
  
  console.log('Starting giant steps...');
  
  for (let i = 0; i <= m; i++) {
    let key;
    if (current.isInfinity()) {
      key = "infinity";
    } else {
      key = current.getX().toString(16);
    }
    
    if (table.has(key)) {
      const j = table.get(key);
      const v = i * m + j;
      
      console.log(`Found match at i=${i}, j=${j} → v=${v}`);
      
      // Verify: v·G = M
      const check = ec.g.mul(new BN(v));
      if (check.eq(M)) {
        console.log(`✅ Verification passed: ${v}·G = M`);
        console.log(`=== DISCRETE LOG SOLVED ===\n`);
        return v;
      } else {
        console.log(`⚠️  Verification failed, continuing search...`);
      }
    }
    
    // M - (i+1)·m·G = M - i·m·G - m·G
    current = current.add(mG.neg());
  }
  
  console.error('Could not solve discrete log');
  console.error(`Point M: x=${M.getX().toString(16)}, y=${M.getY().toString(16)}`);
  console.log(`=== DISCRETE LOG FAILED ===\n`);
  
  throw new Error(`Could not solve discrete log - value exceeds ${maxValue} or invalid point`);
}

/**
 * Generate zero-knowledge proof that encrypted vote is valid (0 or 1 for binary)
 * This proves the voter encrypted either 0 or 1 without revealing which
 * @param {Point} publicKey - ElGamal public key
 * @param {{ c1: Point, c2: Point }} ciphertext 
 * @param {number} voteValue - The actual vote (0 or 1)
 * @param {BN} r - The randomness used in encryption
 * @param {string} context - binds the proof to (ballot, nullifier, option);
 *   without it a ciphertext+proof can be copied into another voter's ballot
 * @returns {Object} Zero-knowledge proof
 */
function proveValidVote(publicKey, ciphertext, voteValue, r, context = "") {
  if (voteValue !== 0 && voteValue !== 1) {
    throw new Error("This proof only works for binary votes (0 or 1)");
  }
  
  const { c1, c2 } = ciphertext;
  
  // Generate random values
  const w = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  const d = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  
  let a1, b1, a2, b2, r1, r2, d1, d2;
  
  if (voteValue === 0) {
    // Real proof for v=0, simulated proof for v=1
    r1 = w; // Real randomness
    a1 = ec.g.mul(w);
    b1 = publicKey.mul(w);
    
    // Simulate for v=1
    d2 = d;
    r2 = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
    const oneG = ec.g;
    a2 = ec.g.mul(r2).add(c1.mul(d2));
    b2 = publicKey.mul(r2).add(c2.add(oneG.neg()).mul(d2));
    
    // Challenge
    const challenge = hashProof(publicKey, c1, c2, a1, b1, a2, b2, context);
    d1 = challenge.sub(d2).umod(ec.curve.n);
    
    // Response for real proof
    r1 = w.sub(d1.mul(r)).umod(ec.curve.n);
    
  } else {
    // Real proof for v=1, simulated proof for v=0
    r2 = w;
    const oneG = ec.g;
    a2 = ec.g.mul(w);
    b2 = publicKey.mul(w);
    
    // Simulate for v=0
    d1 = d;
    r1 = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
    a1 = ec.g.mul(r1).add(c1.mul(d1));
    b1 = publicKey.mul(r1).add(c2.mul(d1));
    
    // Challenge
    const challenge = hashProof(publicKey, c1, c2, a1, b1, a2, b2, context);
    d2 = challenge.sub(d1).umod(ec.curve.n);
    
    // Response for real proof
    r2 = w.sub(d2.mul(r)).umod(ec.curve.n);
  }
  
  return {
    a1: { x: a1.getX().toString(16), y: a1.getY().toString(16) },
    b1: { x: b1.getX().toString(16), y: b1.getY().toString(16) },
    a2: { x: a2.getX().toString(16), y: a2.getY().toString(16) },
    b2: { x: b2.getX().toString(16), y: b2.getY().toString(16) },
    d1: d1.toString(16),
    d2: d2.toString(16),
    r1: r1.toString(16),
    r2: r2.toString(16)
  };
}

/**
 * Verify zero-knowledge proof of valid vote
 */
function verifyValidVote(publicKey, ciphertext, proof, context = "") {
  const { c1, c2 } = ciphertext;

  // Reconstruct points (rejects anything not on the curve)
  const a1 = toPoint(proof.a1);
  const b1 = toPoint(proof.b1);
  const a2 = toPoint(proof.a2);
  const b2 = toPoint(proof.b2);

  const d1 = new BN(proof.d1, 16);
  const d2 = new BN(proof.d2, 16);
  const r1 = new BN(proof.r1, 16);
  const r2 = new BN(proof.r2, 16);

  // Verify challenge
  const challenge = hashProof(publicKey, c1, c2, a1, b1, a2, b2, context);
  const sumD = d1.add(d2).umod(ec.curve.n);
  
  if (!challenge.eq(sumD)) {
    return false;
  }
  
  // Verify proof for v=0
  const check1_a = ec.g.mul(r1).add(c1.mul(d1));
  const check1_b = publicKey.mul(r1).add(c2.mul(d1));
  
  if (!a1.eq(check1_a) || !b1.eq(check1_b)) {
    return false;
  }
  
  // Verify proof for v=1
  const oneG = ec.g;
  const check2_a = ec.g.mul(r2).add(c1.mul(d2));
  const check2_b = publicKey.mul(r2).add(c2.add(oneG.neg()).mul(d2));
  
  if (!a2.eq(check2_a) || !b2.eq(check2_b)) {
    return false;
  }
  
  return true;
}

/**
 * Fiat–Shamir challenge. Hashes the full statement (public key and
 * ciphertext) plus a caller context, following the "strong Fiat–Shamir"
 * requirement (Bernhard–Pereira–Warinschi, ASIACRYPT 2012).
 * Must stay byte-identical to chaincode/identity/lib/ballotCrypto.js.
 */
function hashChallenge(tag, points, context) {
  const data = [tag, ...points.flatMap((p) => [p.getX().toString(16, 64), p.getY().toString(16, 64)]), context].join("|");
  const hash = crypto.createHash("sha256").update(data).digest("hex");
  return new BN(hash, 16).umod(ec.curve.n);
}

function hashProof(publicKey, c1, c2, a1, b1, a2, b2, context = "") {
  return hashChallenge("bbzkv-sigma-or-v1", [publicKey, c1, c2, a1, b1, a2, b2], context);
}

function toPoint(xy) {
  const p = ec.curve.point(new BN(xy.x, 16), new BN(xy.y, 16));
  if (!p.validate()) throw new Error("point not on curve");
  return p;
}

/**
 * Chaum–Pedersen proof that a one-hot vote vector sums to exactly 1:
 * for C = Σ E(v_j) = (R·G, (Σv_j)·G + R·h), prove log_G(C1) = log_h(C2 − G).
 * Without it, every entry can encrypt 1 (overvoting) and each Σ-OR proof
 * still verifies.
 */
function proveSumIsOne(publicKey, ciphertexts, rs, context = "") {
  const R = rs.reduce((acc, r) => acc.add(r), new BN(0)).umod(ec.curve.n);
  const C = ciphertexts.reduce((acc, c) => addCiphertexts(acc, c));
  const w = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  const A = ec.g.mul(w);
  const B = publicKey.mul(w);
  const e = hashChallenge("bbzkv-sum-one-v1", [publicKey, C.c1, C.c2, A, B], context);
  const z = w.add(e.mul(R)).umod(ec.curve.n);
  return {
    A: { x: A.getX().toString(16), y: A.getY().toString(16) },
    B: { x: B.getX().toString(16), y: B.getY().toString(16) },
    z: z.toString(16),
  };
}

function verifySumIsOne(publicKey, ciphertexts, proof, context = "") {
  const C = ciphertexts.reduce((acc, c) => addCiphertexts(acc, c));
  const A = toPoint(proof.A);
  const B = toPoint(proof.B);
  const z = new BN(proof.z, 16);
  const e = hashChallenge("bbzkv-sum-one-v1", [publicKey, C.c1, C.c2, A, B], context);
  return ec.g.mul(z).eq(A.add(C.c1.mul(e))) &&
         publicKey.mul(z).eq(B.add(C.c2.add(ec.g.neg()).mul(e)));
}

/**
 * Verifiable decryption (Chaum–Pedersen DLEQ): proves M = c2 − x·c1 for the
 * same x with h = x·G, i.e. log_G(h) = log_{c1}(c2 − M), without revealing x.
 * Anyone can then check the published total T against M = T·G.
 */
// The total T fixes M = T·G (M may be the point at infinity, which has no
// affine coordinates), so T itself goes into the challenge.
const decryptContext = (ballotId, option, total) => `${ballotId}|${option}|T=${total}|decrypt`;
const totalPoint = (total) => (total === 0 ? ec.curve.point(null, null) : ec.g.mul(new BN(total)));

function proveDecryption(keypair, ciphertext, total, context) {
  const { c1 } = ciphertext;
  const w = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  const A = ec.g.mul(w);
  const B = c1.mul(w);
  const e = hashChallenge("bbzkv-decrypt-v1", [keypair.publicKey, c1, ciphertext.c2, A, B], context);
  return {
    A: { x: A.getX().toString(16), y: A.getY().toString(16) },
    B: { x: B.getX().toString(16), y: B.getY().toString(16) },
    z: w.add(e.mul(keypair.privateKey)).umod(ec.curve.n).toString(16),
  };
}

function verifyDecryption(publicKey, ciphertext, total, proof, context) {
  const { c1, c2 } = ciphertext;
  const A = toPoint(proof.A);
  const B = toPoint(proof.B);
  const z = new BN(proof.z, 16);
  const e = hashChallenge("bbzkv-decrypt-v1", [publicKey, c1, c2, A, B], context);
  return ec.g.mul(z).eq(A.add(publicKey.mul(e))) &&
         c1.mul(z).eq(B.add(c2.add(totalPoint(total).neg()).mul(e)));
}

// Proof contexts — the chaincode recomputes these from (ballotId, nullifier)
const optionContext = (ballotId, nullifier, j) => `${ballotId}|${nullifier}|opt${j}`;
const sumContext = (ballotId, nullifier) => `${ballotId}|${nullifier}|sum`;

/**
 * Build the full encrypted ballot for a one-hot choice:
 *   { ciphertexts: [{c1, c2, validityProof}], sumProof }
 */
function encryptBallot(publicKey, numOptions, choiceIndex, ballotId, nullifier) {
  const raw = [];
  const ciphertexts = [];
  for (let j = 0; j < numOptions; j++) {
    const m = j === choiceIndex ? 1 : 0;
    const c = encrypt(publicKey, m);
    raw.push(c);
    const s = serializeCiphertext(c);
    s.validityProof = proveValidVote(publicKey, c, m, c.r, optionContext(ballotId, nullifier, j));
    ciphertexts.push(s);
  }
  const sumProof = proveSumIsOne(publicKey, raw, raw.map((c) => c.r), sumContext(ballotId, nullifier));
  return { ciphertexts, sumProof };
}

/**
 * voteBinding public input: 248-bit digest of (ballotId, ciphertexts), so
 * the SNARK cannot be replayed with substituted ciphertexts.
 * Must stay byte-identical to chaincode/identity/lib/ballotCrypto.js.
 */
function computeVoteBinding(ballotId, encryptedBallot) {
  const cts = encryptedBallot.ciphertexts
    .map((c) => [c.c1.x, c.c1.y, c.c2.x, c.c2.y].join(":"))
    .join(",");
  const hex = crypto.createHash("sha256")
    .update(`bbzkv-vote-binding-v1|${ballotId}|${cts}`)
    .digest("hex");
  return BigInt("0x" + hex.slice(0, 62));
}

/**
 * Serialize ciphertext for storage
 */
function serializeCiphertext(ciphertext) {
  return {
    c1: {
      x: ciphertext.c1.getX().toString(16),
      y: ciphertext.c1.getY().toString(16)
    },
    c2: {
      x: ciphertext.c2.getX().toString(16),
      y: ciphertext.c2.getY().toString(16)
    }
  };
}

/**
 * Deserialize ciphertext from storage
 */
function deserializeCiphertext(data) {
  if (!data || !data.c1 || !data.c2) {
    throw new Error('Invalid ciphertext data');
  }
  
  return {
    c1: toPoint(data.c1),
    c2: toPoint(data.c2)
  };
}

/**
 * Serialize keypair
 */
function serializeKeypair(keypair) {
  return {
    privateKey: keypair.privateKey.toString(16),
    publicKey: {
      x: keypair.publicKey.getX().toString(16),
      y: keypair.publicKey.getY().toString(16)
    }
  };
}

/**
 * Deserialize keypair
 */
function deserializeKeypair(data) {
  return {
    privateKey: new BN(data.privateKey, 16),
    publicKey: ec.curve.point(
      new BN(data.publicKey.x, 16),
      new BN(data.publicKey.y, 16)
    )
  };
}

module.exports = {
  generateKeypair,
  encrypt,
  decrypt,
  addCiphertexts,
  solveDiscreteLog,
  encodeVote,
  proveValidVote,
  verifyValidVote,
  proveSumIsOne,
  verifySumIsOne,
  proveDecryption,
  verifyDecryption,
  decryptContext,
  optionContext,
  sumContext,
  encryptBallot,
  computeVoteBinding,
  serializeCiphertext,
  deserializeCiphertext,
  serializeKeypair,
  deserializeKeypair
};