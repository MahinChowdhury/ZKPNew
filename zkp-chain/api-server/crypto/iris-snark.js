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
const { execFile } = require("child_process");
const util = require("util");
const os = require("os");

const execFileAsync = util.promisify(execFile);

// Import shared utilities from the face snark module
const faceSnark = require("./snark");

// ============================================================
// Paths to compiled IRIS circuit artifacts
// ============================================================
const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
const IRIS_WASM_PATH = path.join(CIRCUITS_DIR, "iris_auth_js", "iris_auth.wasm");
const IRIS_ZKEY_PATH = path.join(CIRCUITS_DIR, "iris_auth.zkey");
const IRIS_VKEY_PATH = path.join(CIRCUITS_DIR, "iris_verification_key.json");

const RAPIDSNARK_PROVER = path.join(CIRCUITS_DIR, "rapidsnark", "package", "bin", "prover");
const IRIS_CPP_WITNESS_GEN = path.join(CIRCUITS_DIR, "iris_auth_cpp", "iris_auth");

// ============================================================
// Constants
// ============================================================
const IRIS_CODE_SIZE = 256;       // Downsampled iris code dimension
const MERKLE_TREE_LEVELS = 20;    // Same depth as face tree, but independent
const HAMMING_THRESHOLD = 123;    // floor(0.478 * 256) + 1 = 123 (strict <)
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

/**
 * Generate a ZK-SNARK proof for iris biometric authentication.
 *
 * @param {number[]} irisCodeLive256 - live iris code (256 bits, downsampled)
 * @param {number[]} irisCodeReg256 - registered iris code (256 bits, downsampled)
 * @param {BigInt} salt - registration salt
 * @param {BigInt} secretKey - voter's secret key
 * @param {BigInt} irisHash - Poseidon hash of registered iris code
 * @param {BigInt} merkleRoot - Merkle tree root (iris tree)
 * @param {BigInt[]} pathElements - Merkle proof siblings
 * @param {number[]} pathIndices - Merkle proof directions
 * @param {BigInt} electionId - unique election identifier
 * @param {BigInt} nullifier - precomputed nullifier
 * @param {number} hammingThreshold - max allowed Hamming distance (default 123)
 * @returns {Promise<{proof, publicSignals}>}
 */
async function generateIrisProof(
  irisCodeLive256,
  irisCodeReg256,
  salt,
  secretKey,
  irisHash,
  merkleRoot,
  pathElements,
  pathIndices,
  electionId,
  nullifier,
  hammingThreshold = HAMMING_THRESHOLD
) {
  // Validate circuit artifacts
  if (!fs.existsSync(IRIS_WASM_PATH)) {
    throw new Error(
      `Iris circuit WASM not found at ${IRIS_WASM_PATH}. Run: cd circuits && bash build_iris_circuit.sh`
    );
  }
  if (!fs.existsSync(IRIS_ZKEY_PATH)) {
    throw new Error(
      `Iris proving key not found at ${IRIS_ZKEY_PATH}. Run: cd circuits && bash build_iris_circuit.sh`
    );
  }

  // Build witness input
  const input = {
    // Public inputs
    irisHash: toFieldString(irisHash),
    merkleRoot: toFieldString(merkleRoot),
    nullifier: toFieldString(nullifier),
    electionId: toFieldString(electionId),
    hammingThreshold: hammingThreshold.toString(),

    // Private inputs
    irisCodeLive: irisCodeLive256.map((b) => b.toString()),
    irisCodeRegistered: irisCodeReg256.map((b) => b.toString()),
    salt: toFieldString(salt),
    secretKey: toFieldString(secretKey),
    pathElements: pathElements.map(toFieldString),
    pathIndices: pathIndices.map(toFieldString),
  };

  console.log("\n=== IRIS SNARK PROOF GENERATION (Merkle + Nullifier) ===");
  console.log(`Iris code size: ${irisCodeLive256.length}`);
  console.log(`irisHash: ${irisHash.toString().slice(0, 20)}...`);
  console.log(`merkleRoot: ${merkleRoot.toString().slice(0, 20)}...`);
  console.log(`nullifier: ${nullifier.toString().slice(0, 20)}...`);
  console.log(`electionId: ${electionId.toString()}`);
  console.log(`hammingThreshold: ${hammingThreshold}`);

  const startTime = Date.now();

  let proof;
  let publicSignals;

  // Check if rapidsnark is installed
  const useRapidsnark = fs.existsSync(RAPIDSNARK_PROVER);
  const useCppWitness = fs.existsSync(IRIS_CPP_WITNESS_GEN);

  if (useRapidsnark) {
    console.log("  ⚡ Using rapidsnark C++ native prover");
    if (useCppWitness) {
      console.log("  ⚡ Using C++ native witness generator (iris)");
    }

    const tmpDir = os.tmpdir();
    const nonce = crypto.randomBytes(8).toString("hex");
    const inputPath = path.join(tmpDir, `iris_input_${nonce}.json`);
    const wtnsPath = path.join(tmpDir, `iris_witness_${nonce}.wtns`);
    const proofPath = path.join(tmpDir, `iris_proof_${nonce}.json`);
    const publicPath = path.join(tmpDir, `iris_public_${nonce}.json`);

    try {
      fs.writeFileSync(inputPath, JSON.stringify(input));

      const wtnsStart = Date.now();
      if (useCppWitness) {
        await execFileAsync(IRIS_CPP_WITNESS_GEN, [inputPath, wtnsPath]);
      } else {
        console.log("  (Fallback) Using WASM witness generator");
        await snarkjs.wtns.calculate(input, IRIS_WASM_PATH, wtnsPath);
      }
      console.log(`  ⏱️  Witness generation: ${Date.now() - wtnsStart}ms`);

      const proveStart = Date.now();
      await execFileAsync(RAPIDSNARK_PROVER, [
        IRIS_ZKEY_PATH,
        wtnsPath,
        proofPath,
        publicPath,
      ]);
      console.log(`  ⏱️  Proof generation: ${Date.now() - proveStart}ms`);

      proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
      publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
    } finally {
      [inputPath, wtnsPath, proofPath, publicPath].forEach((p) => {
        if (fs.existsSync(p)) {
          try {
            fs.unlinkSync(p);
          } catch (e) {}
        }
      });
    }
  } else {
    console.log("  🐢 Using snarkjs pure WASM prover (fallback)");

    if (!_irisWasmBuffer) {
      _irisWasmBuffer = new Uint8Array(fs.readFileSync(IRIS_WASM_PATH));
    }
    if (!_irisZkeyBuffer) {
      _irisZkeyBuffer = new Uint8Array(fs.readFileSync(IRIS_ZKEY_PATH));
    }

    const result = await snarkjs.groth16.fullProve(
      input,
      _irisWasmBuffer,
      _irisZkeyBuffer
    );
    proof = result.proof;
    publicSignals = result.publicSignals;
  }

  const elapsed = Date.now() - startTime;
  console.log(`✅ Iris proof generated in ${elapsed}ms`);
  console.log(`Public signals: ${publicSignals.length} values`);
  console.log("=== IRIS SNARK PROOF COMPLETE ===\n");

  return { proof, publicSignals };
}

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

/**
 * Compute all iris registration data.
 *
 * @param {number[]} irisCode - full iris code from Python (0/1 array, ~196K)
 * @param {number[]} noiseMask - noise mask from Python (0/1 array, same length)
 * @param {string} saltHex - random hex salt string
 * @returns {Promise<{irisHash, secretKey, commitment, salt, irisCode256}>}
 */
async function computeIrisRegistrationData(irisCode, noiseMask, saltHex) {
  // 1. Downsample to 256 bits
  const irisCode256 = downsampleIrisCode(irisCode, noiseMask);

  // 2. Convert salt hex to BigInt
  const salt = BigInt("0x" + saltHex);

  // 3. Compute Poseidon hash
  const irisHash = await poseidonHashIrisCode(irisCode256, salt);

  // 4. Generate random secret key
  const secretKey = faceSnark.generateSecretKey();

  // 5. Compute commitment = Poseidon(irisHash, secretKey)
  const commitment = await computeIrisCommitment(irisHash, secretKey);

  return { irisHash, secretKey, commitment, salt, irisCode256 };
}

// ============================================================
// Convenience: full pipeline for login/vote proof
// ============================================================

/**
 * Generate a full iris authentication proof with independent Merkle tree.
 *
 * @param {number[]} liveIrisCode - live iris code from Python (full, ~196K bits)
 * @param {number[]} liveNoiseMask - live noise mask
 * @param {number[]} registeredIrisCode256 - saved downsampled code (256 bits)
 * @param {string} saltHex - registration salt (hex string)
 * @param {BigInt} irisHash - pre-computed Poseidon hash
 * @param {BigInt} secretKey - voter's secret key
 * @param {BigInt[]} irisCommitments - all registered iris commitments
 * @param {BigInt} electionId - unique election identifier
 * @returns {Promise<{proof, publicSignals, isValid, nullifier, merkleRoot}>}
 */
async function generateIrisAuthProof(
  liveIrisCode,
  liveNoiseMask,
  registeredIrisCode256,
  saltHex,
  irisHash,
  secretKey,
  irisCommitments,
  electionId
) {
  const totalStart = Date.now();
  const timings = {};

  // Downsample live iris code to 256 bits
  let t0 = Date.now();
  const liveCode256 = downsampleIrisCode(liveIrisCode, liveNoiseMask);
  timings.downsample = Date.now() - t0;

  // Convert salt
  const salt = BigInt("0x" + saltHex);

  // Compute the voter's commitment
  t0 = Date.now();
  const commitment = await computeIrisCommitment(irisHash, secretKey);
  timings.commitment = Date.now() - t0;

  // Find the voter's leaf index
  const leafIndex = irisCommitments.findIndex((c) => c === commitment);
  if (leafIndex === -1) {
    throw new Error(
      "Iris commitment not found in the registered iris commitments. User may not be registered with iris."
    );
  }

  console.log(
    `Iris voter leaf index: ${leafIndex} out of ${irisCommitments.length} iris commitments`
  );

  // Build independent iris Merkle tree
  t0 = Date.now();
  const { root, layers, zeroHashes } = await buildIrisMerkleTree(irisCommitments);
  timings.merkleTree = Date.now() - t0;

  t0 = Date.now();
  const { pathElements, pathIndices } = getIrisMerkleProof(
    layers,
    zeroHashes,
    leafIndex
  );
  timings.merkleProof = Date.now() - t0;

  // Compute nullifier
  t0 = Date.now();
  const nullifier = await computeIrisNullifier(secretKey, electionId);
  timings.nullifier = Date.now() - t0;

  // Generate SNARK proof
  t0 = Date.now();
  const { proof, publicSignals } = await generateIrisProof(
    liveCode256,
    registeredIrisCode256,
    salt,
    secretKey,
    irisHash,
    root,
    pathElements,
    pathIndices,
    electionId,
    nullifier,
    HAMMING_THRESHOLD
  );
  timings.snarkProve = Date.now() - t0;

  // Verify locally
  t0 = Date.now();
  const isValid = await verifyIrisProof(proof, publicSignals);
  timings.snarkVerify = Date.now() - t0;

  const totalElapsed = Date.now() - totalStart;
  console.log(`\n⏱️  IRIS AUTH PROOF TIMING BREAKDOWN:`);
  console.log(`  Iris downsampling:  ${timings.downsample}ms`);
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
  generateIrisProof,
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

  // Pipeline helpers
  computeIrisRegistrationData,
  generateIrisAuthProof,
};
