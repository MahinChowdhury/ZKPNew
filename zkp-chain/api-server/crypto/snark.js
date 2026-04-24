// ============================================================
// crypto/snark.js — ZK-SNARK proof generation & verification
// Architecture: Merkle Tree + Nullifier (Semaphore-style)
// Uses: snarkjs (Groth16), circomlibjs (Poseidon), ffjavascript
// ============================================================

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { execFile } = require("child_process");
const util = require("util");
const os = require("os");

const execFileAsync = util.promisify(execFile);

// ============================================================
// Paths to compiled circuit artifacts
// ============================================================
const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
const WASM_PATH = path.join(CIRCUITS_DIR, "face_auth_js", "face_auth.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "face_auth.zkey");
const VKEY_PATH = path.join(CIRCUITS_DIR, "verification_key.json");

const RAPIDSNARK_PROVER = path.join(CIRCUITS_DIR, "rapidsnark", "package", "bin", "prover");
const CPP_WITNESS_GEN = path.join(CIRCUITS_DIR, "face_auth_cpp", "face_auth");

// ============================================================
// Constants
// ============================================================
const MERKLE_TREE_LEVELS = 20; // Supports up to 2^20 ~ 1M voters
const SCALE_FACTOR = 1000000; // 1e6
const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toFieldString(val) {
  let v = BigInt(val);
  if (v < 0n) {
    v = (v % BN128_PRIME) + BN128_PRIME;
  }
  return (v % BN128_PRIME).toString();
}

// ============================================================
// Cache verification key and circuit artifacts
// ============================================================
let _vkey = null;
let _wasmBuffer = null;
let _zkeyBuffer = null;

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

/**
 * Generate a random secret key (252 bits to fit safely in BN128 field)
 * @returns {BigInt}
 */
function generateSecretKey() {
  const bytes = crypto.randomBytes(32);
  let sk = BigInt("0x" + bytes.toString("hex"));
  // Mask to 252 bits to stay safely within the BN128 field
  sk = sk & ((1n << 252n) - 1n);
  if (sk === 0n) sk = 1n;
  return sk;
}

// ============================================================
// Proof generation
// ============================================================

/**
 * Generate a ZK-SNARK proof of biometric authentication + Merkle membership + nullifier
 *
 * @param {BigInt[]} embedding - live face embedding (integer-scaled, 64 elements)
 * @param {BigInt[]} registeredEmbedding - registered face embedding (integer-scaled)
 * @param {BigInt} salt - registration salt
 * @param {BigInt} secretKey - voter's secret key
 * @param {BigInt} faceHash - Poseidon hash commitment
 * @param {BigInt} merkleRoot - Merkle tree root
 * @param {BigInt[]} pathElements - Merkle proof sibling hashes
 * @param {number[]} pathIndices - Merkle proof directions (0=left, 1=right)
 * @param {BigInt} electionId - unique election identifier
 * @param {BigInt} nullifier - precomputed nullifier
 * @param {BigInt} threshold_sq_num - squared threshold numerator (e.g. 25)
 * @param {BigInt} threshold_sq_den - squared threshold denominator (e.g. 100)
 * @returns {Promise<{proof: Object, publicSignals: string[]}>}
 */
async function generateProof(
  embedding,
  registeredEmbedding,
  salt,
  secretKey,
  faceHash,
  merkleRoot,
  pathElements,
  pathIndices,
  electionId,
  nullifier,
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
    faceHash: toFieldString(faceHash),
    merkleRoot: toFieldString(merkleRoot),
    nullifier: toFieldString(nullifier),
    electionId: toFieldString(electionId),
    threshold_sq_num: toFieldString(threshold_sq_num),
    threshold_sq_den: toFieldString(threshold_sq_den),

    // Private inputs
    embedding: embedding.map(toFieldString),
    registeredEmbedding: registeredEmbedding.map(toFieldString),
    salt: toFieldString(salt),
    secretKey: toFieldString(secretKey),
    pathElements: pathElements.map(toFieldString),
    pathIndices: pathIndices.map(toFieldString),
  };

  console.log("\n=== SNARK PROOF GENERATION (Merkle + Nullifier) ===");
  console.log(`Embedding size: ${embedding.length}`);
  console.log(`faceHash: ${faceHash.toString().slice(0, 20)}...`);
  console.log(`merkleRoot: ${merkleRoot.toString().slice(0, 20)}...`);
  console.log(`nullifier: ${nullifier.toString().slice(0, 20)}...`);
  console.log(`electionId: ${electionId.toString()}`);

  const startTime = Date.now();

  let proof;
  let publicSignals;

  // Check if rapidsnark is installed
  const useRapidsnark = fs.existsSync(RAPIDSNARK_PROVER);
  const useCppWitness = fs.existsSync(CPP_WITNESS_GEN);

  if (useRapidsnark) {
    console.log("  ⚡ Using rapidsnark C++ native prover for 10-50x speedup");
    if (useCppWitness) {
      console.log("  ⚡ Using C++ native witness generator");
    }

    // Temporary files for IPC with native binaries
    const tmpDir = os.tmpdir();
    const nonce = crypto.randomBytes(8).toString('hex');
    const inputPath = path.join(tmpDir, `zkp_input_${nonce}.json`);
    const wtnsPath = path.join(tmpDir, `zkp_witness_${nonce}.wtns`);
    const proofPath = path.join(tmpDir, `zkp_proof_${nonce}.json`);
    const publicPath = path.join(tmpDir, `zkp_public_${nonce}.json`);

    try {
      // Write input JSON to disk for the witness generator
      fs.writeFileSync(inputPath, JSON.stringify(input));

      // 1. Generate Witness (.wtns)
      const wtnsStart = Date.now();
      if (useCppWitness) {
        // Fastest: C++ witness generator
        await execFileAsync(CPP_WITNESS_GEN, [inputPath, wtnsPath]);
      } else {
        // Fallback: snarkjs WASM witness generator (writing to file)
        console.log("  (Fallback) Using WASM witness generator");
        await snarkjs.wtns.calculate(input, WASM_PATH, wtnsPath);
      }
      console.log(`  ⏱️  Witness generation: ${Date.now() - wtnsStart}ms`);

      // 2. Generate Proof via rapidsnark
      const proveStart = Date.now();
      await execFileAsync(RAPIDSNARK_PROVER, [ZKEY_PATH, wtnsPath, proofPath, publicPath]);
      console.log(`  ⏱️  Proof generation: ${Date.now() - proveStart}ms`);

      // Read output files
      proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
      publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));

    } finally {
      // Clean up temporary files
      [inputPath, wtnsPath, proofPath, publicPath].forEach(p => {
        if (fs.existsSync(p)) {
          try { fs.unlinkSync(p); } catch(e) {}
        }
      });
    }

  } else {
    // Fallback to pure WASM / NodeJS
    console.log("  🐢 Using snarkjs pure WASM prover (fallback)");

    // Cache artifacts in memory to prevent heavy I/O on every proof
    if (!_wasmBuffer) {
      _wasmBuffer = new Uint8Array(fs.readFileSync(WASM_PATH));
    }
    if (!_zkeyBuffer) {
      _zkeyBuffer = new Uint8Array(fs.readFileSync(ZKEY_PATH));
    }

    // Generate proof using Groth16 in pure Node/WASM
    const result = await snarkjs.groth16.fullProve(
      input,
      _wasmBuffer,
      _zkeyBuffer
    );
    proof = result.proof;
    publicSignals = result.publicSignals;
  }

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

  return isValid;
}

// ============================================================
// Convenience: full pipeline for registration
// ============================================================

/**
 * Compute all registration data
 * @param {number[]} embeddingFloat - raw float64 embedding from FaceNet
 * @param {string} saltHex - random hex salt string
 * @returns {Promise<{faceHash, secretKey, commitment, salt, embeddingScaled}>}
 */
async function computeRegistrationData(embeddingFloat, saltHex) {
  // 1. Scale embedding to integers
  const embeddingScaled = scaleEmbedding(embeddingFloat);

  // 2. Convert salt hex to BigInt
  const salt = BigInt("0x" + saltHex);

  // 3. Compute Poseidon hash
  const faceHash = await poseidonHashEmbedding(embeddingScaled, salt);

  // 4. Generate random secret key
  const secretKey = generateSecretKey();

  // 5. Compute commitment = Poseidon(faceHash, secretKey)
  const commitment = await computeCommitment(faceHash, secretKey);

  return { faceHash, secretKey, commitment, salt, embeddingScaled };
}

// ============================================================
// Convenience: full pipeline for login/vote proof
// ============================================================

/**
 * Generate a full authentication proof with Merkle membership + nullifier
 *
 * @param {number[]} liveEmbeddingFloat - live face embedding (float)
 * @param {number[]} registeredEmbeddingFloat - registered face embedding (float)
 * @param {string} saltHex - registration salt (hex string)
 * @param {BigInt} faceHash - pre-computed Poseidon hash
 * @param {BigInt} secretKey - voter's secret key
 * @param {BigInt[]} commitments - all registered commitments (for building Merkle tree)
 * @param {BigInt} electionId - unique election identifier
 * @returns {Promise<{proof, publicSignals, isValid, nullifier, merkleRoot}>}
 */
async function generateAuthProof(
  liveEmbeddingFloat,
  registeredEmbeddingFloat,
  saltHex,
  faceHash,
  secretKey,
  commitments,
  electionId
) {
  const totalStart = Date.now();
  const timings = {};

  // Scale embeddings
  let t0 = Date.now();
  const liveScaled = scaleEmbedding(liveEmbeddingFloat);
  const regScaled = scaleEmbedding(registeredEmbeddingFloat);
  timings.scaling = Date.now() - t0;

  // Convert salt
  const salt = BigInt("0x" + saltHex);

  // Compute the voter's commitment
  t0 = Date.now();
  const commitment = await computeCommitment(faceHash, secretKey);
  timings.commitment = Date.now() - t0;

  // Find the voter's leaf index in the commitments array
  const leafIndex = commitments.findIndex((c) => c === commitment);
  if (leafIndex === -1) {
    throw new Error(
      "Voter commitment not found in the registered commitments. User may not be registered."
    );
  }

  console.log(`Voter leaf index: ${leafIndex} out of ${commitments.length} commitments`);

  // Build Merkle tree and get proof (OPTIMIZED — sparse tree)
  t0 = Date.now();
  const { root, layers, zeroHashes } = await buildMerkleTreeOptimized(commitments);
  timings.merkleTree = Date.now() - t0;

  t0 = Date.now();
  const { pathElements, pathIndices } = getMerkleProofOptimized(layers, zeroHashes, leafIndex);
  timings.merkleProof = Date.now() - t0;

  // Compute nullifier
  t0 = Date.now();
  const nullifier = await computeNullifier(secretKey, electionId);
  timings.nullifier = Date.now() - t0;

  // Threshold: cosine sim >= 0.5 → squared = 0.25 → 25/100
  const threshold_sq_num = 25n;
  const threshold_sq_den = 100n;

  // Generate SNARK proof (Groth16)
  t0 = Date.now();
  const { proof, publicSignals } = await generateProof(
    liveScaled,
    regScaled,
    salt,
    secretKey,
    faceHash,
    root,
    pathElements,
    pathIndices,
    electionId,
    nullifier,
    threshold_sq_num,
    threshold_sq_den
  );
  timings.snarkProve = Date.now() - t0;

  // Verify locally
  t0 = Date.now();
  const isValid = await verifyProof(proof, publicSignals);
  timings.snarkVerify = Date.now() - t0;

  const totalElapsed = Date.now() - totalStart;
  console.log(`\n⏱️  AUTH PROOF TIMING BREAKDOWN:`);
  console.log(`  Embedding scaling:  ${timings.scaling}ms`);
  console.log(`  Commitment compute: ${timings.commitment}ms`);
  console.log(`  Merkle tree build:  ${timings.merkleTree}ms`);
  console.log(`  Merkle proof gen:   ${timings.merkleProof}ms`);
  console.log(`  Nullifier compute:  ${timings.nullifier}ms`);
  console.log(`  SNARK proof gen:    ${timings.snarkProve}ms`);
  console.log(`  SNARK verification: ${timings.snarkVerify}ms`);
  console.log(`  ─────────────────────────────`);
  console.log(`  TOTAL:              ${totalElapsed}ms\n`);

  return { proof, publicSignals, isValid, nullifier, merkleRoot: root };
}

module.exports = {
  // Core functions
  generateProof,
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
  generateSecretKey,

  // Embedding utilities
  scaleEmbedding,
  SCALE_FACTOR,

  // Pipeline helpers
  computeRegistrationData,
  generateAuthProof,
};
