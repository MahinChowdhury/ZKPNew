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
 * @returns {Object} Zero-knowledge proof
 */
function proveValidVote(publicKey, ciphertext, voteValue, r) {
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
    const challenge = hashProof(c1, c2, a1, b1, a2, b2);
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
    const challenge = hashProof(c1, c2, a1, b1, a2, b2);
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
function verifyValidVote(publicKey, ciphertext, proof) {
  const { c1, c2 } = ciphertext;
  
  // Reconstruct points
  const a1 = ec.curve.point(new BN(proof.a1.x, 16), new BN(proof.a1.y, 16));
  const b1 = ec.curve.point(new BN(proof.b1.x, 16), new BN(proof.b1.y, 16));
  const a2 = ec.curve.point(new BN(proof.a2.x, 16), new BN(proof.a2.y, 16));
  const b2 = ec.curve.point(new BN(proof.b2.x, 16), new BN(proof.b2.y, 16));
  
  const d1 = new BN(proof.d1, 16);
  const d2 = new BN(proof.d2, 16);
  const r1 = new BN(proof.r1, 16);
  const r2 = new BN(proof.r2, 16);
  
  // Verify challenge
  const challenge = hashProof(c1, c2, a1, b1, a2, b2);
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
 * Hash function for challenge in ZK proof
 */
function hashProof(c1, c2, a1, b1, a2, b2) {
  const data = [
    c1.getX().toString(16, 64),
    c1.getY().toString(16, 64),
    c2.getX().toString(16, 64),
    c2.getY().toString(16, 64),
    a1.getX().toString(16, 64),
    a1.getY().toString(16, 64),
    b1.getX().toString(16, 64),
    b1.getY().toString(16, 64),
    a2.getX().toString(16, 64),
    a2.getY().toString(16, 64),
    b2.getX().toString(16, 64),
    b2.getY().toString(16, 64)
  ].join('');
  
  const hash = crypto.createHash("sha256").update(data).digest("hex");
  return new BN(hash, 16).umod(ec.curve.n);
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
    c1: ec.curve.point(new BN(data.c1.x, 16), new BN(data.c1.y, 16)),
    c2: ec.curve.point(new BN(data.c2.x, 16), new BN(data.c2.y, 16))
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
  serializeCiphertext,
  deserializeCiphertext,
  serializeKeypair,
  deserializeKeypair
};