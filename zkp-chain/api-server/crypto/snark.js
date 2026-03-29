// ============================================================
// crypto/snark.js — ZK-SNARK proof generation & verification
// Uses: snarkjs (PLONK), circomlibjs (Poseidon), ffjavascript
// ============================================================

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");

// ============================================================
// Paths to compiled circuit artifacts
// ============================================================
const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
const WASM_PATH = path.join(CIRCUITS_DIR, "face_auth_js", "face_auth.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "face_auth.zkey");
const VKEY_PATH = path.join(CIRCUITS_DIR, "verification_key.json");

// ============================================================
// Cache verification key
// ============================================================
let _vkey = null;

function getVerificationKey() {
  if (!_vkey) {
    if (!fs.existsSync(VKEY_PATH)) {
      throw new Error(
        `Verification key not found at ${VKEY_PATH}. Run: cd circuits && bash build_circuit.sh`
      );
    }
    _vkey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));
  }
  return _vkey;
}

// ============================================================
// Poseidon hash (mirrors the circuit logic exactly)
// ============================================================

let _poseidon = null;
let _F = null;

async function initPoseidon() {
  if (!_poseidon) {
    const circomlibjs = require("circomlibjs");
    _poseidon = await circomlibjs.buildPoseidon();
    _F = _poseidon.F;
  }
  return { poseidon: _poseidon, F: _F };
}

/**
 * Compute Poseidon hash of a 64-element embedding + salt
 * Mirrors PoseidonHashChunked(64, 8) in the circuit:
 *   1. Hash each chunk of 8 elements
 *   2. Hash the 8 intermediate digests
 *   3. Hash(embeddingHash, salt)
 *
 * @param {BigInt[]} embedding - 64 integer-scaled embedding values
 * @param {BigInt} salt - salt value
 * @returns {Promise<BigInt>} Poseidon hash as field element
 */
async function poseidonHashEmbedding(embedding, salt) {
  const { poseidon, F } = await initPoseidon();

  if (embedding.length !== 64) {
    throw new Error(`Expected 64-element embedding, got ${embedding.length}`);
  }

  // Step 1: Hash 8 chunks of 8 elements each
  const chunkHashes = [];
  for (let i = 0; i < 8; i++) {
    const chunk = embedding.slice(i * 8, (i + 1) * 8);
    const h = poseidon(chunk.map((v) => F.e(v)));
    chunkHashes.push(h);
  }

  // Step 2: Hash the 8 chunk digests
  const embeddingHash = poseidon(chunkHashes);

  // Step 3: Hash(embeddingHash, salt)
  const finalHash = poseidon([embeddingHash, F.e(salt)]);

  return F.toObject(finalHash);
}

// ============================================================
// Baby Jubjub key derivation
// ============================================================

let _babyJub = null;

async function initBabyJub() {
  if (!_babyJub) {
    const circomlibjs = require("circomlibjs");
    _babyJub = await circomlibjs.buildBabyjub();
  }
  return _babyJub;
}

/**
 * Derive Baby Jubjub public key S = k * G (base point)
 * @param {BigInt} k - private scalar
 * @returns {Promise<{Sx: BigInt, Sy: BigInt}>}
 */
async function deriveBabyJubKey(k) {
  const babyJub = await initBabyJub();
  const F = babyJub.F;

  // BabyPbk in circomlib uses Base8 as generator
  const pubKey = babyJub.mulPointEscalar(babyJub.Base8, k);

  return {
    Sx: F.toObject(pubKey[0]),
    Sy: F.toObject(pubKey[1]),
  };
}

// ============================================================
// Embedding scaling utilities
// ============================================================

const SCALE_FACTOR = 1000000; // 1e6

/**
 * Scale float embedding to integer for circuit
 * @param {number[]} embedding - float array
 * @returns {BigInt[]} integer-scaled array
 */
function scaleEmbedding(embedding) {
  return embedding.map((v) => {
    // Scale and round
    const scaled = Math.round(v * SCALE_FACTOR);
    // Convert to BigInt, handle negatives via field arithmetic
    return BigInt(scaled);
  });
}

// ============================================================
// Key derivation (Poseidon-based, replaces SHA-256 deriveK)
// ============================================================

/**
 * Derive private scalar k from faceHash + salt via Poseidon
 * @param {BigInt} faceHash - Poseidon hash of embedding
 * @param {BigInt} salt - registration salt
 * @returns {Promise<BigInt>} scalar k for Baby Jubjub
 */
async function deriveScalarK(faceHash, salt) {
  const { poseidon, F } = await initPoseidon();

  // k = Poseidon(faceHash, salt, 1) — the "1" domain-separates from faceHash computation
  const kHash = poseidon([F.e(faceHash), F.e(salt), F.e(1n)]);
  let k = F.toObject(kHash);

  // Ensure k != 0 (extremely unlikely but safety check)
  if (k === 0n) k = 1n;

  return k;
}

// ============================================================
// Proof generation
// ============================================================

/**
 * Generate a ZK-SNARK proof of biometric authentication
 *
 * @param {BigInt[]} embedding - live face embedding (integer-scaled, 64 elements)
 * @param {BigInt[]} registeredEmbedding - registered face embedding (integer-scaled)
 * @param {BigInt} k - private scalar
 * @param {BigInt} salt - registration salt
 * @param {BigInt} faceHash - Poseidon hash commitment
 * @param {BigInt} Sx - public key x (Baby Jubjub)
 * @param {BigInt} Sy - public key y (Baby Jubjub)
 * @param {BigInt} threshold_sq_num - squared threshold numerator (e.g. 25)
 * @param {BigInt} threshold_sq_den - squared threshold denominator (e.g. 100)
 * @returns {Promise<{proof: Object, publicSignals: string[]}>}
 */
async function generateProof(
  embedding,
  registeredEmbedding,
  k,
  salt,
  faceHash,
  Sx,
  Sy,
  threshold_sq_num = 25n,
  threshold_sq_den = 100n
) {
  // Validate circuit artifacts exist
  if (!fs.existsSync(WASM_PATH)) {
    throw new Error(
      `Circuit WASM not found at ${WASM_PATH}. Run: cd circuits && bash build_circuit.sh`
    );
  }
  if (!fs.existsSync(ZKEY_PATH)) {
    throw new Error(
      `Proving key not found at ${ZKEY_PATH}. Run: cd circuits && bash build_circuit.sh`
    );
  }

  // Build witness input
  const input = {
    // Public inputs
    faceHash: faceHash.toString(),
    Sx: Sx.toString(),
    Sy: Sy.toString(),
    threshold_sq_num: threshold_sq_num.toString(),
    threshold_sq_den: threshold_sq_den.toString(),

    // Private inputs
    embedding: embedding.map((v) => v.toString()),
    registeredEmbedding: registeredEmbedding.map((v) => v.toString()),
    k: k.toString(),
    salt: salt.toString(),
  };

  console.log("\n=== SNARK PROOF GENERATION ===");
  console.log(`Embedding size: ${embedding.length}`);
  console.log(`faceHash: ${faceHash.toString().slice(0, 20)}...`);
  console.log(`Public key: (${Sx.toString().slice(0, 16)}..., ${Sy.toString().slice(0, 16)}...)`);

  const startTime = Date.now();

  // Generate proof using PLONK
  const { proof, publicSignals } = await snarkjs.plonk.fullProve(
    input,
    WASM_PATH,
    ZKEY_PATH
  );

  const elapsed = Date.now() - startTime;
  console.log(`✅ Proof generated in ${elapsed}ms`);
  console.log(`Public signals: ${publicSignals.length} values`);
  console.log("=== SNARK PROOF COMPLETE ===\n");

  return { proof, publicSignals };
}

// ============================================================
// Proof verification
// ============================================================

/**
 * Verify a ZK-SNARK proof
 * @param {Object} proof - PLONK proof object
 * @param {string[]} publicSignals - array of public signal strings
 * @returns {Promise<boolean>} true if proof is valid
 */
async function verifyProof(proof, publicSignals) {
  const vkey = getVerificationKey();

  console.log("\n=== SNARK PROOF VERIFICATION ===");
  const startTime = Date.now();

  const isValid = await snarkjs.plonk.verify(vkey, publicSignals, proof);

  const elapsed = Date.now() - startTime;
  console.log(`Verification result: ${isValid} (${elapsed}ms)`);
  console.log("=== SNARK VERIFICATION COMPLETE ===\n");

  return isValid;
}

// ============================================================
// Convenience: full pipeline for registration
// ============================================================

/**
 * Compute all registration data using SNARK-compatible primitives
 * @param {number[]} embeddingFloat - raw float64 embedding from FaceNet
 * @param {string} saltHex - random hex salt string
 * @returns {Promise<{faceHash, k, Sx, Sy, salt, embeddingScaled}>}
 */
async function computeRegistrationData(embeddingFloat, saltHex) {
  // 1. Scale embedding to integers
  const embeddingScaled = scaleEmbedding(embeddingFloat);

  // 2. Convert salt hex to BigInt
  const salt = BigInt("0x" + saltHex);

  // 3. Compute Poseidon hash
  const faceHash = await poseidonHashEmbedding(embeddingScaled, salt);

  // 4. Derive private key k
  const k = await deriveScalarK(faceHash, salt);

  // 5. Derive Baby Jubjub public key
  const { Sx, Sy } = await deriveBabyJubKey(k);

  return { faceHash, k, Sx, Sy, salt, embeddingScaled };
}

// ============================================================
// Convenience: full pipeline for login/vote proof
// ============================================================

/**
 * Generate a full authentication proof
 * @param {number[]} liveEmbeddingFloat - live face embedding (float)
 * @param {number[]} registeredEmbeddingFloat - registered face embedding (float)
 * @param {string} saltHex - registration salt (hex string)
 * @param {BigInt} faceHash - pre-computed Poseidon hash
 * @param {BigInt} Sx - registered Baby Jubjub public key x
 * @param {BigInt} Sy - registered Baby Jubjub public key y
 * @returns {Promise<{proof, publicSignals, isValid}>}
 */
async function generateAuthProof(
  liveEmbeddingFloat,
  registeredEmbeddingFloat,
  saltHex,
  faceHash,
  Sx,
  Sy
) {
  // Scale embeddings
  const liveScaled = scaleEmbedding(liveEmbeddingFloat);
  const regScaled = scaleEmbedding(registeredEmbeddingFloat);

  // Convert salt
  const salt = BigInt("0x" + saltHex);

  // Derive k from the live embedding's hash (should match registered if same person)
  // Important: k is derived from REGISTERED embedding hash, not live
  const k = await deriveScalarK(faceHash, salt);

  // Threshold: cosine sim >= 0.5 → squared = 0.25 → 25/100
  const threshold_sq_num = 25n;
  const threshold_sq_den = 100n;

  // Generate proof
  const { proof, publicSignals } = await generateProof(
    liveScaled,
    regScaled,
    k,
    salt,
    faceHash,
    Sx,
    Sy,
    threshold_sq_num,
    threshold_sq_den
  );

  // Verify locally
  const isValid = await verifyProof(proof, publicSignals);

  return { proof, publicSignals, isValid };
}

module.exports = {
  // Core functions
  generateProof,
  verifyProof,
  getVerificationKey,

  // Poseidon utilities
  poseidonHashEmbedding,
  initPoseidon,

  // Baby Jubjub utilities
  deriveBabyJubKey,
  deriveScalarK,

  // Embedding utilities
  scaleEmbedding,
  SCALE_FACTOR,

  // Pipeline helpers
  computeRegistrationData,
  generateAuthProof,
};
