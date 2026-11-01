// ============================================================
// crypto/iris-snark.js — ZK-SNARK proof generation & verification
//                        for Iris biometric authentication
// Architecture: Independent Merkle Tree + Nullifier
// Uses: snarkjs (Groth16), circomlibjs (Poseidon)
// ============================================================

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// Import shared utilities from the face snark module
const faceSnark = require("./snark");

// ============================================================
// Paths to compiled IRIS circuit artifacts
// ============================================================
const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
const IRIS_VKEY_PATH = path.join(CIRCUITS_DIR, "iris_verification_key.json");

// ============================================================
// Constants
// ============================================================
const IRIS_CODE_SIZE = 256;       // Downsampled iris code dimension
const MERKLE_TREE_LEVELS = 20;    // Same depth as face tree, but independent
const HAMMING_THRESHOLD = 123;    // floor(0.478 * 256) + 1 = 123 (strict <)
const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ============================================================
// Cache verification key and circuit artifacts
// ============================================================
let _irisVkey = null;
let _irisWasmBuffer = null;
let _irisZkeyBuffer = null;

// Independent iris Merkle tree caches
let _irisZeroHashes = null;
let _cachedIrisTree = null;
let _cachedIrisTreeFingerprint = null;

function getIrisVerificationKey() {
  if (!_irisVkey) {
    if (!fs.existsSync(IRIS_VKEY_PATH)) {
      throw new Error(
        `Iris verification key not found at ${IRIS_VKEY_PATH}. Run: cd circuits && bash build_iris_circuit.sh`
      );
    }
    _irisVkey = JSON.parse(fs.readFileSync(IRIS_VKEY_PATH, "utf8"));
  }
  return _irisVkey;
}

// ============================================================
// Iris code downsampling
// ============================================================

/**
 * Downsample a full iris code (196,608 bits) to 256 bits.
 * Uniformly samples from positions where the noise mask is 1 (valid).
 *
 * @param {number[]} fullCode - full iris code (0/1 array, ~196K elements)
 * @param {number[]} fullMask - noise mask (0/1 array, same length)
 * @returns {number[]} downsampled iris code (256 elements, 0/1)
 */
function downsampleIrisCode(fullCode, fullMask) {
  // Collect indices where mask is valid (1)
  const validIndices = [];
  for (let i = 0; i < fullCode.length; i++) {
    if (fullMask[i] === 1) {
      validIndices.push(i);
    }
  }

  if (validIndices.length < IRIS_CODE_SIZE) {
    // If fewer valid bits than target, pad with bits from anywhere
    console.warn(
      `⚠ Only ${validIndices.length} valid iris bits (need ${IRIS_CODE_SIZE}). Using all available + zero-padded.`
    );
    const code256 = new Array(IRIS_CODE_SIZE).fill(0);
    for (let i = 0; i < Math.min(validIndices.length, IRIS_CODE_SIZE); i++) {
      code256[i] = fullCode[validIndices[i]];
    }
    return code256;
  }

  // Uniformly sample IRIS_CODE_SIZE positions from valid indices
  const code256 = new Array(IRIS_CODE_SIZE);
  const step = validIndices.length / IRIS_CODE_SIZE;

  for (let i = 0; i < IRIS_CODE_SIZE; i++) {
    const idx = validIndices[Math.floor(i * step)];
    code256[i] = fullCode[idx] ? 1 : 0;
  }

  return code256;
}

// ============================================================
// Poseidon hash for iris code (mirrors circuit logic exactly)
// ============================================================

/**
 * Compute Poseidon hash of a 256-bit iris code + salt.
 * Mirrors the circuit:
 *   1. Pack 256 bits into 32 bytes (Bits2Num(8) per group)
 *   2. PoseidonHashChunked(32, 8): 4 chunks of 8 → Poseidon(4)
 *   3. Poseidon(embeddingHash, salt)
 *
 * @param {number[]} irisCode256 - 256-element binary array
 * @param {BigInt} salt - salt value
 * @returns {Promise<BigInt>} Poseidon hash as field element
 */
async function poseidonHashIrisCode(irisCode256, salt) {
  const { poseidon, F } = await faceSnark.initPoseidon();

  if (irisCode256.length !== IRIS_CODE_SIZE) {
    throw new Error(`Expected ${IRIS_CODE_SIZE}-bit iris code, got ${irisCode256.length}`);
  }

  // Step 1: Pack 256 bits into 32 packed byte values
  const packed = [];
  for (let i = 0; i < 32; i++) {
    let val = 0;
    for (let j = 0; j < 8; j++) {
      val += irisCode256[i * 8 + j] * (1 << j);
    }
    packed.push(BigInt(val));
  }

  // Step 2: PoseidonHashChunked(32, 8) — 4 chunks of 8
  const numChunks = 4; // 32 / 8
  const chunkHashes = [];
  for (let i = 0; i < numChunks; i++) {
    const chunk = packed.slice(i * 8, (i + 1) * 8);
    const h = poseidon(chunk.map((v) => F.e(v)));
    chunkHashes.push(h);
  }

  // Step 3: Hash the 4 chunk digests
  const irisHashRaw = poseidon(chunkHashes);

  // Step 4: Hash(irisHash, salt)
  const finalHash = poseidon([irisHashRaw, F.e(salt)]);

  return F.toObject(finalHash);
}

// ============================================================
// Independent iris Merkle tree (sparse, cached)
// ============================================================

/**
 * Pre-compute zero hashes for the iris Merkle tree.
 * Independent cache from the face tree.
 */
async function getIrisZeroHashes() {
  if (!_irisZeroHashes) {
    _irisZeroHashes = [0n];
    for (let i = 0; i < MERKLE_TREE_LEVELS; i++) {
      _irisZeroHashes.push(
        await faceSnark.poseidonHash2(_irisZeroHashes[i], _irisZeroHashes[i])
      );
    }
    console.log(`  ⚡ Iris zero hashes pre-computed for ${MERKLE_TREE_LEVELS} levels`);
  }
  return _irisZeroHashes;
}

function irisCommitmentsFingerprint(commitments) {
  const hash = crypto.createHash("sha256");
  for (const c of commitments) {
    hash.update(c.toString() + ",");
  }
  return hash.digest("hex");
}

/**
 * Build a sparse Poseidon Merkle tree for iris commitments.
 * Completely independent from the face Merkle tree.
 */
async function buildIrisMerkleTree(commitments) {
  const fingerprint = irisCommitmentsFingerprint(commitments);
  if (_cachedIrisTree && _cachedIrisTreeFingerprint === fingerprint) {
    console.log("  ⚡ Iris Merkle tree cache HIT — skipping rebuild");
    return _cachedIrisTree;
  }

  const zeroHashes = await getIrisZeroHashes();
  const startTime = Date.now();

  // Layer 0: sparse Map of non-zero leaves
  const layers = [new Map()];
  for (let i = 0; i < commitments.length; i++) {
    if (commitments[i] !== 0n) {
      layers[0].set(i, commitments[i]);
    }
  }

  // Build bottom-up
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
      nextLayer.set(parentIdx, await faceSnark.poseidonHash2(left, right));
    }

    layers.push(nextLayer);
  }

  const root = layers[MERKLE_TREE_LEVELS].has(0)
    ? layers[MERKLE_TREE_LEVELS].get(0)
    : zeroHashes[MERKLE_TREE_LEVELS];

  const elapsed = Date.now() - startTime;
  const totalNodes = layers.reduce((sum, layer) => sum + layer.size, 0);
  console.log(
    `  ⚡ Iris sparse Merkle tree: ${elapsed}ms, ${totalNodes} nodes hashed`
  );

  const result = { root, layers, zeroHashes };
  _cachedIrisTree = result;
  _cachedIrisTreeFingerprint = fingerprint;

  return result;
}

function getIrisMerkleProof(layers, zeroHashes, leafIndex) {
  const pathElements = [];
  const pathIndices = [];
  let currentIndex = leafIndex;

  for (let level = 0; level < MERKLE_TREE_LEVELS; level++) {
    const isRight = currentIndex % 2;
    const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

    const sibling = layers[level].has(siblingIndex)
      ? layers[level].get(siblingIndex)
      : zeroHashes[level];

    pathElements.push(sibling);
    pathIndices.push(isRight ? 1 : 0);

    currentIndex = Math.floor(currentIndex / 2);
  }

  return { pathElements, pathIndices };
}

/**
 * Invalidate the iris Merkle tree cache (call after new iris registration)
 */
function invalidateIrisMerkleCache() {
  _cachedIrisTree = null;
  _cachedIrisTreeFingerprint = null;
  console.log("  🔄 Iris Merkle tree cache invalidated");
}

// ============================================================
// Commitment & Nullifier (reuse Poseidon from face module)
// ============================================================

async function computeIrisCommitment(irisHash, secretKey) {
  return faceSnark.computeCommitment(irisHash, secretKey);
}

async function computeIrisNullifier(secretKey, electionId) {
  return faceSnark.computeNullifier(secretKey, electionId);
}

// ============================================================
// Proof generation
// ============================================================

// ============================================================
// Proof verification
// ============================================================

async function verifyIrisProof(proof, publicSignals) {
  const vkey = getIrisVerificationKey();

  console.log("\n=== IRIS SNARK PROOF VERIFICATION ===");
  const startTime = Date.now();

  const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  const elapsed = Date.now() - startTime;
  console.log(`Verification result: ${isValid} (${elapsed}ms)`);
  console.log("=== IRIS SNARK VERIFICATION COMPLETE ===\n");

  return isValid;
}

// ============================================================
// Convenience: full pipeline for registration
// ============================================================

// ============================================================
// Convenience: full pipeline for login/vote proof
// ============================================================

module.exports = {
  // Core functions
  verifyIrisProof,
  getIrisVerificationKey,

  // Iris code processing
  downsampleIrisCode,
  poseidonHashIrisCode,
  IRIS_CODE_SIZE,
  HAMMING_THRESHOLD,

  // Poseidon (delegates to face snark)
  initPoseidon: faceSnark.initPoseidon,

  // Independent iris Merkle tree
  buildIrisMerkleTree,
  getIrisMerkleProof,
  getIrisZeroHashes,
  invalidateIrisMerkleCache,
  MERKLE_TREE_LEVELS,

  // Commitment & Nullifier
  computeIrisCommitment,
  computeIrisNullifier,
};
