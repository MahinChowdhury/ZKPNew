// ============================================================
// crypto/snark.js — server-side ZK-SNARK verification and Merkle helpers
// (proving runs in the voter client: frontend/src/crypto/voterClient.js)
// Architecture: Merkle Tree + Nullifier (Semaphore-style)
// Uses: snarkjs (Groth16), circomlibjs (Poseidon), ffjavascript
// ============================================================

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// ============================================================
// Paths to compiled circuit artifacts
// ============================================================
const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
const VKEY_PATH = path.join(CIRCUITS_DIR, "verification_key.json");

// ============================================================
// Constants
// ============================================================
const MERKLE_TREE_LEVELS = 20; // Supports up to 2^20 ~ 1M voters
const SCALE_FACTOR = 500000; // 5e5, matches the circuit range check |x| < 2^19
const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ============================================================
// Cache verification key and circuit artifacts
// ============================================================
let _vkey = null;

// Sparse Merkle tree caches
let _zeroHashes = null;
let _cachedTree = null;
let _cachedTreeFingerprint = null;

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
 * Compute the salted Poseidon hash of an integer-scaled embedding.
 * Mirrors PackedCoordHash(d, 19) in the circuit:
 *   1. Pack offset coordinates x + 2^19 into 20-bit slots, 12 per field element
 *   2. Poseidon over the packed elements (one per 16 for d > 192)
 *   3. Hash(embeddingHash, salt)
 *
 * @param {BigInt[]} embedding - integer-scaled embedding values, |x| < 2^19
 * @param {BigInt} salt - salt value
 * @returns {Promise<BigInt>} Poseidon hash as field element
 */
async function poseidonHashEmbedding(embedding, salt) {
  const { poseidon, F } = await initPoseidon();
  const off = 1n << 19n;

  const packed = [];
  for (let e = 0; e * 12 < embedding.length; e++) {
    let v = 0n;
    for (let j = 0; j < 12 && e * 12 + j < embedding.length; j++) {
      const x = BigInt(embedding[e * 12 + j]);
      if (x < -off || x >= off) throw new Error(`Coordinate ${x} outside the circuit range`);
      v += (x + off) << (20n * BigInt(j));
    }
    packed.push(F.e(v));
  }

  let embeddingHash;
  if (packed.length <= 16) {
    embeddingHash = poseidon(packed);
  } else {
    const groups = [];
    for (let q = 0; q < packed.length; q += 16) groups.push(poseidon(packed.slice(q, q + 16)));
    embeddingHash = poseidon(groups);
  }

  const finalHash = poseidon([embeddingHash, F.e(salt)]);
  return F.toObject(finalHash);
}

// ============================================================
// Embedding scaling utilities
// ============================================================

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
// Merkle Tree (Poseidon-based binary tree)
// ============================================================

/**
 * Compute Poseidon hash of two children (for Merkle tree)
 * @param {BigInt} left
 * @param {BigInt} right
 * @returns {Promise<BigInt>}
 */
async function poseidonHash2(left, right) {
  const { poseidon, F } = await initPoseidon();
  const h = poseidon([F.e(left), F.e(right)]);
  return F.toObject(h);
}

// ============================================================
// Dense Merkle Tree (LEGACY — kept for backward compatibility)
// WARNING: O(2^levels) hashes — extremely slow for large trees
// ============================================================

async function buildMerkleTree(leaves) {
  const targetSize = Math.pow(2, MERKLE_TREE_LEVELS);
  const paddedLeaves = [...leaves];
  while (paddedLeaves.length < targetSize) {
    paddedLeaves.push(0n);
  }
  const layers = [paddedLeaves];
  let currentLayer = paddedLeaves;
  for (let level = 0; level < MERKLE_TREE_LEVELS; level++) {
    const nextLayer = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      const hash = await poseidonHash2(currentLayer[i], currentLayer[i + 1]);
      nextLayer.push(hash);
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }
  return { root: layers[layers.length - 1][0], layers };
}

function getMerkleProof(layers, leafIndex) {
  const pathElements = [];
  const pathIndices = [];
  let currentIndex = leafIndex;
  for (let level = 0; level < MERKLE_TREE_LEVELS; level++) {
    const isRight = currentIndex % 2;
    const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
    pathElements.push(layers[level][siblingIndex]);
    pathIndices.push(isRight ? 1 : 0);
    currentIndex = Math.floor(currentIndex / 2);
  }
  return { pathElements, pathIndices };
}

// ============================================================
// Optimized Sparse Merkle Tree
// Instead of building a full 2^20 tree (~1,048,575 Poseidon hashes),
// this uses pre-computed zero subtree hashes and only processes
// paths containing actual (non-zero) leaves.
//
// Complexity: O(N * levels) instead of O(2^levels)
//   - 10 voters, 20 levels: ~200 hashes vs ~1,048,575
//   - Speedup: ~5,000x on tree construction alone
// ============================================================

/**
 * Pre-compute the hash of an empty subtree at each level.
 * zeroHashes[0] = 0n (empty leaf)
 * zeroHashes[i] = Poseidon(zeroHashes[i-1], zeroHashes[i-1])
 * Computed once and cached permanently.
 */
async function getZeroHashes() {
  if (!_zeroHashes) {
    _zeroHashes = [0n];
    for (let i = 0; i < MERKLE_TREE_LEVELS; i++) {
      _zeroHashes.push(await poseidonHash2(_zeroHashes[i], _zeroHashes[i]));
    }
    console.log(`  ⚡ Zero hashes pre-computed for ${MERKLE_TREE_LEVELS} levels`);
  }
  return _zeroHashes;
}

/**
 * Fast fingerprint of commitments array for cache invalidation.
 */
function commitmentsFingerprint(commitments) {
  const hash = crypto.createHash('sha256');
  for (const c of commitments) {
    hash.update(c.toString() + ',');
  }
  return hash.digest('hex');
}

/**
 * Build a sparse Poseidon Merkle tree.
 * Only hashes paths containing non-zero leaves; uses pre-computed
 * zero hashes for all-empty subtrees. Results are cached.
 *
 * @param {BigInt[]} commitments - actual voter commitments
 * @returns {Promise<{root: BigInt, layers: Map<number,BigInt>[], zeroHashes: BigInt[]}>}
 */
async function buildMerkleTreeOptimized(commitments) {
  // Check cache first
  const fingerprint = commitmentsFingerprint(commitments);
  if (_cachedTree && _cachedTreeFingerprint === fingerprint) {
    console.log("  ⚡ Merkle tree cache HIT — skipping rebuild");
    return _cachedTree;
  }

  const zeroHashes = await getZeroHashes();
  const startTime = Date.now();

  // Layer 0: store actual leaves in a sparse Map
  const layers = [new Map()];
  for (let i = 0; i < commitments.length; i++) {
    if (commitments[i] !== 0n) {
      layers[0].set(i, commitments[i]);
    }
  }

  // Build tree bottom-up — only hash where at least one child is non-zero
  for (let level = 0; level < MERKLE_TREE_LEVELS; level++) {
    const nextLayer = new Map();
    const currentLayer = layers[level];

    // Collect unique parent indices
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

  const elapsed = Date.now() - startTime;
  const totalNodes = layers.reduce((sum, layer) => sum + layer.size, 0);
  console.log(`  ⚡ Sparse Merkle tree: ${elapsed}ms, ${totalNodes} nodes hashed (vs ~1,048,575 in dense tree)`);

  const result = { root, layers, zeroHashes };

  // Cache for subsequent votes
  _cachedTree = result;
  _cachedTreeFingerprint = fingerprint;

  return result;
}

/**
 * Generate Merkle proof from sparse tree layers.
 * Uses zero hashes for missing siblings.
 */
function getMerkleProofOptimized(layers, zeroHashes, leafIndex) {
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
 * Invalidate the Merkle tree cache (call after new voter registration)
 */
function invalidateMerkleCache() {
  _cachedTree = null;
  _cachedTreeFingerprint = null;
  console.log("  🔄 Merkle tree cache invalidated");
}

// ============================================================
// Commitment & Nullifier computation
// ============================================================

/**
 * Compute a voter commitment leaf
 *   commitment = Poseidon(faceHash, secretKey)
 *
 * @param {BigInt} faceHash - Poseidon hash of embedding + salt
 * @param {BigInt} secretKey - voter's random secret key
 * @returns {Promise<BigInt>}
 */
async function computeCommitment(faceHash, secretKey) {
  const { poseidon, F } = await initPoseidon();
  const h = poseidon([F.e(faceHash), F.e(secretKey)]);
  return F.toObject(h);
}

/**
 * Compute the nullifier for double-vote prevention
 *   nullifier = Poseidon(secretKey, electionId)
 *
 * @param {BigInt} secretKey - voter's secret key
 * @param {BigInt} electionId - unique election identifier
 * @returns {Promise<BigInt>}
 */
async function computeNullifier(secretKey, electionId) {
  const { poseidon, F } = await initPoseidon();
  const h = poseidon([F.e(secretKey), F.e(electionId)]);
  return F.toObject(h);
}

// ============================================================
// Proof generation
// ============================================================

// ============================================================
// Proof verification
// ============================================================

/**
 * Verify a ZK-SNARK proof
 * @param {Object} proof - Groth16 proof object
 * @param {string[]} publicSignals - array of public signal strings
 * @returns {Promise<boolean>} true if proof is valid
 */
async function verifyProof(proof, publicSignals) {
  const vkey = getVerificationKey();

  console.log("\n=== SNARK PROOF VERIFICATION ===");
  const startTime = Date.now();

  const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  const elapsed = Date.now() - startTime;
  console.log(`Verification result: ${isValid} (${elapsed}ms)`);
  console.log("=== SNARK VERIFICATION COMPLETE ===\n");

  require("fs").writeFileSync("proof.json", JSON.stringify(proof));
  require("fs").writeFileSync("public.json", JSON.stringify(publicSignals));

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
  verifyProof,
  getVerificationKey,

  // Poseidon utilities
  poseidonHashEmbedding,
  initPoseidon,
  poseidonHash2,

  // Merkle tree (legacy dense — kept for backward compat)
  buildMerkleTree,
  getMerkleProof,
  MERKLE_TREE_LEVELS,

  // Merkle tree (optimized sparse)
  buildMerkleTreeOptimized,
  getMerkleProofOptimized,
  getZeroHashes,
  invalidateMerkleCache,

  // Commitment & Nullifier
  computeCommitment,
  computeNullifier,

  // Embedding utilities
  scaleEmbedding,
  SCALE_FACTOR,
};
