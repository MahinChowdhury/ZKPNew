#!/usr/bin/env node
// ============================================================
// benchmark_paper.js — Publication-Grade ZKP Benchmarking Suite
//
// Methodology (Reviewer-2-proof):
//   • Timing metrics: 100 iterations (configurable via --runs)
//   • 3 warm-up runs discarded (JIT, cache priming)
//   • 5% trimmed mean: drop top 5% + bottom 5% outliers
//   • Report: trimmed_mean ± standard_deviation
//   • Interleaved Face/Iris runs to control thermal throttling
//   • Deterministic metrics (R1CS, gas): single-shot (invariant)
//
// Collects ALL metrics needed for Q1 journal paper:
//   Category 1: Circuit Complexity (R1CS constraints) — 1 run
//   Category 2: Computational Latency — 100 runs, trimmed
//   Category 3: Storage & Payload Size — 1 run (deterministic)
//   Category 4: On-Chain Metrics (gas) — 1 run (deterministic)
//
// Run from api-server/:
//   node compareBenchmarks/benchmark_paper.js              # 100 runs
//   node compareBenchmarks/benchmark_paper.js --runs 50    # quick
//   node compareBenchmarks/benchmark_paper.js --json       # + stdout JSON
// ============================================================

const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { execFile, execSync } = require("child_process");
const util = require("util");
const os = require("os");

const execFileAsync = util.promisify(execFile);

// Import crypto modules (one level up from compareBenchmarks/)
const faceSnark = require("../crypto/snark");
const irisSnark = require("../crypto/iris-snark");

// ============================================================
// Configuration
// ============================================================
const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
const OUTPUT_DIR = __dirname; // Results saved in compareBenchmarks/

// Parse CLI args
const args = process.argv.slice(2);
const NUM_RUNS = parseInt(args.find((_, i, a) => a[i - 1] === "--runs") || "100");
const JSON_OUTPUT = args.includes("--json");
const NUM_VOTERS = 10; // Simulated voter pool for Merkle tree
const WARMUP_RUNS = 3; // Discarded to account for JIT / cold cache
const TRIM_PERCENT = 0.05; // Drop top 5% + bottom 5% outliers

// File paths
const FACE_R1CS = path.join(CIRCUITS_DIR, "face_auth.r1cs");
const FACE_WASM = path.join(CIRCUITS_DIR, "face_auth_js", "face_auth.wasm");
const FACE_ZKEY = path.join(CIRCUITS_DIR, "face_auth.zkey");
const FACE_VKEY = path.join(CIRCUITS_DIR, "verification_key.json");
const FACE_CPP_WITNESS = path.join(CIRCUITS_DIR, "face_auth_cpp", "face_auth");

const IRIS_R1CS = path.join(CIRCUITS_DIR, "iris_auth.r1cs");
const IRIS_WASM = path.join(CIRCUITS_DIR, "iris_auth_js", "iris_auth.wasm");
const IRIS_ZKEY = path.join(CIRCUITS_DIR, "iris_auth.zkey");
const IRIS_VKEY = path.join(CIRCUITS_DIR, "iris_verification_key.json");
const IRIS_CPP_WITNESS = path.join(CIRCUITS_DIR, "iris_auth_cpp", "iris_auth");

const FACE_SOL = path.join(CIRCUITS_DIR, "PlonkVerifier.sol");
const IRIS_SOL = path.join(CIRCUITS_DIR, "IrisVerifier.sol");

// ============================================================
// Helpers
// ============================================================

const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toFieldString(val) {
  let v = BigInt(val);
  if (v < 0n) v = (v % BN128_PRIME) + BN128_PRIME;
  return (v % BN128_PRIME).toString();
}

function generateFakeEmbedding(seed = 42) {
  const emb = new Array(64);
  let state = seed;
  for (let i = 0; i < 64; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    emb[i] = (state / 0x7fffffff) * 2 - 1;
  }
  const norm = Math.sqrt(emb.reduce((s, v) => s + v * v, 0));
  return emb.map((v) => v / norm);
}

function addNoise(embedding, noiseLevel = 0.05) {
  const noisy = embedding.map(
    (v) => v + (Math.random() - 0.5) * noiseLevel
  );
  const norm = Math.sqrt(noisy.reduce((s, v) => s + v * v, 0));
  return noisy.map((v) => v / norm);
}

function generateFakeIrisCode256(seed = 42) {
  const code = new Array(256);
  let state = seed;
  for (let i = 0; i < 256; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    code[i] = state % 2;
  }
  return code;
}

function addIrisNoise(code, flipRate = 0.10) {
  return code.map((bit) => (Math.random() < flipRate ? 1 - bit : bit));
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatMs(ms) {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function median(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function mean(arr) {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr) {
  const m = mean(arr);
  return Math.sqrt(arr.reduce((s, v) => s + (v - m) ** 2, 0) / arr.length);
}

/**
 * 5% Trimmed Mean: sort, drop lowest 5% and highest 5%, then average.
 * This removes outliers from CPU thermal throttling, OS interrupts, etc.
 * This is the value you report in your paper.
 */
function trimmedMean(arr, trimFrac = TRIM_PERCENT) {
  const sorted = [...arr].sort((a, b) => a - b);
  const trimCount = Math.floor(sorted.length * trimFrac);
  const trimmed = sorted.slice(trimCount, sorted.length - trimCount);
  if (trimmed.length === 0) return mean(sorted); // fallback if array too small
  return mean(trimmed);
}

/**
 * Standard deviation of the trimmed set (for reporting ± σ).
 */
function trimmedStddev(arr, trimFrac = TRIM_PERCENT) {
  const sorted = [...arr].sort((a, b) => a - b);
  const trimCount = Math.floor(sorted.length * trimFrac);
  const trimmed = sorted.slice(trimCount, sorted.length - trimCount);
  if (trimmed.length === 0) return stddev(sorted);
  return stddev(trimmed);
}

/**
 * Compute full statistics suite for an array of measurements.
 */
function computeStats(arr) {
  return {
    raw: arr,
    n: arr.length,
    min: Math.min(...arr),
    max: Math.max(...arr),
    median: median(arr),
    mean: mean(arr),
    std: stddev(arr),
    trimmedMean: trimmedMean(arr),
    trimmedStd: trimmedStddev(arr),
    trimPercent: TRIM_PERCENT * 100,
    trimmedN: arr.length - 2 * Math.floor(arr.length * TRIM_PERCENT),
  };
}

/**
 * Format for paper: "125 ± 14 ms"
 */
function formatPaperMs(stats) {
  const val = stats.trimmedMean;
  const sd = stats.trimmedStd;
  if (val < 1000) return `${val.toFixed(0)} ± ${sd.toFixed(0)} ms`;
  return `${(val / 1000).toFixed(2)} ± ${(sd / 1000).toFixed(2)} s`;
}

function progressBar(current, total, width = 40) {
  const pct = current / total;
  const filled = Math.round(width * pct);
  const bar = "█".repeat(filled) + "░".repeat(width - filled);
  return `[${bar}] ${current}/${total}`;
}

// ============================================================
// Category 1: Circuit Complexity
// ============================================================

async function getR1CSInfo(r1csPath, label) {
  console.log(`\n📐 Analyzing ${label} circuit (${path.basename(r1csPath)})...`);

  const r1cs = await snarkjs.r1cs.info(r1csPath);

  // r1cs.info returns the info logged to console; parse from the r1cs object
  // We can also read the r1cs directly
  const r1csData = await snarkjs.r1cs.exportJson(r1csPath);

  const info = {
    label,
    nConstraints: r1csData.nConstraints,
    nVars: r1csData.nVars,
    nOutputs: r1csData.nOutputs,
    nPubInputs: r1csData.nPubInputs,
    nPrvInputs: r1csData.nPrvInputs,
    nLabels: r1csData.nLabels,
    prime: r1csData.prime ? r1csData.prime.toString() : "bn128",
    // Non-linear constraints = constraints with at least one multiplication
    // In R1CS Ax * Bx = Cx, every constraint IS a multiplication
    nNonLinearConstraints: r1csData.nConstraints, // All R1CS constraints are bilinear
    r1csFileSize: fs.statSync(r1csPath).size,
  };

  return info;
}

// ============================================================
// Category 2: Computational Latency
// ============================================================

async function benchmarkFaceProof(regData, commitments, electionId, run) {
  const registeredEmb = generateFakeEmbedding(42);
  const liveEmb = addNoise(registeredEmb, 0.05);

  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";
  const salt = BigInt("0x" + saltHex);

  // --- Pre-compute data ---
  const liveScaled = faceSnark.scaleEmbedding(liveEmb);
  const regScaled = faceSnark.scaleEmbedding(registeredEmb);
  const commitment = await faceSnark.computeCommitment(
    regData.faceHash,
    regData.secretKey
  );
  const leafIndex = commitments.findIndex((c) => c === commitment);
  const nullifier = await faceSnark.computeNullifier(
    regData.secretKey,
    electionId
  );

  // Build Merkle tree
  let t0 = Date.now();
  const { root, layers, zeroHashes } =
    await faceSnark.buildMerkleTreeOptimized(commitments);
  const merkleTime = Date.now() - t0;

  const { pathElements, pathIndices } = faceSnark.getMerkleProofOptimized(
    layers,
    zeroHashes,
    leafIndex
  );

  // Build witness input
  const input = {
    faceHash: toFieldString(regData.faceHash),
    merkleRoot: toFieldString(root),
    nullifier: toFieldString(nullifier),
    electionId: toFieldString(electionId),
    threshold_sq_num: toFieldString(25n),
    threshold_sq_den: toFieldString(100n),
    embedding: liveScaled.map(toFieldString),
    registeredEmbedding: regScaled.map(toFieldString),
    salt: toFieldString(salt),
    secretKey: toFieldString(regData.secretKey),
    pathElements: pathElements.map(toFieldString),
    pathIndices: pathIndices.map(toFieldString),
  };

  const timings = {};

  // --- Witness Generation ---
  const useCpp = fs.existsSync(FACE_CPP_WITNESS);
  const tmpDir = os.tmpdir();
  const nonce = crypto.randomBytes(8).toString("hex");
  const inputPath = path.join(tmpDir, `bench_face_input_${nonce}.json`);
  const wtnsPath = path.join(tmpDir, `bench_face_witness_${nonce}.wtns`);
  const proofPath = path.join(tmpDir, `bench_face_proof_${nonce}.json`);
  const publicPath = path.join(tmpDir, `bench_face_public_${nonce}.json`);

  try {
    fs.writeFileSync(inputPath, JSON.stringify(input));

    // Witness generation
    t0 = Date.now();
    if (useCpp) {
      await execFileAsync(FACE_CPP_WITNESS, [inputPath, wtnsPath]);
    } else {
      await snarkjs.wtns.calculate(input, FACE_WASM, wtnsPath);
    }
    timings.witnessGen = Date.now() - t0;

    // Proof generation
    const useRapidsnark = fs.existsSync(
      path.join(CIRCUITS_DIR, "rapidsnark", "package", "bin", "prover")
    );

    if (useRapidsnark) {
      const prover = path.join(
        CIRCUITS_DIR,
        "rapidsnark",
        "package",
        "bin",
        "prover"
      );
      t0 = Date.now();
      await execFileAsync(prover, [
        FACE_ZKEY,
        wtnsPath,
        proofPath,
        publicPath,
      ]);
      timings.proofGen = Date.now() - t0;
      timings.prover = "rapidsnark (C++)";
    } else {
      const wasmBuf = new Uint8Array(fs.readFileSync(FACE_WASM));
      const zkeyBuf = new Uint8Array(fs.readFileSync(FACE_ZKEY));
      t0 = Date.now();
      const result = await snarkjs.groth16.fullProve(input, wasmBuf, zkeyBuf);
      timings.proofGen = Date.now() - t0;
      timings.prover = "snarkjs (WASM)";
      fs.writeFileSync(proofPath, JSON.stringify(result.proof));
      fs.writeFileSync(publicPath, JSON.stringify(result.publicSignals));
    }

    // Read proof for size measurement and verification
    const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));

    timings.proofSize = Buffer.byteLength(JSON.stringify(proof));
    timings.publicSignalsCount = publicSignals.length;

    // Proof verification
    const vkey = JSON.parse(fs.readFileSync(FACE_VKEY, "utf8"));
    t0 = Date.now();
    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    timings.proofVerify = Date.now() - t0;
    timings.isValid = isValid;
    timings.merkleTime = merkleTime;
    timings.witnessGenerator = useCpp ? "C++ native" : "WASM";
  } finally {
    [inputPath, wtnsPath, proofPath, publicPath].forEach((p) => {
      try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) {}
    });
  }

  return timings;
}

async function benchmarkIrisProof(regData, commitments, electionId, run) {
  const registeredCode = generateFakeIrisCode256(42);
  const liveCode = addIrisNoise(registeredCode, 0.10);

  const saltHex = "b1c2d3e4f5a6789012345678abcdef02";
  const salt = BigInt("0x" + saltHex);

  // --- Pre-compute data ---
  const commitment = await irisSnark.computeIrisCommitment(
    regData.irisHash,
    regData.secretKey
  );
  const leafIndex = commitments.findIndex((c) => c === commitment);
  const nullifier = await irisSnark.computeIrisNullifier(
    regData.secretKey,
    electionId
  );

  // Build Merkle tree
  let t0 = Date.now();
  const { root, layers, zeroHashes } =
    await irisSnark.buildIrisMerkleTree(commitments);
  const merkleTime = Date.now() - t0;

  const { pathElements, pathIndices } = irisSnark.getIrisMerkleProof(
    layers,
    zeroHashes,
    leafIndex
  );

  // Build witness input
  const input = {
    irisHash: toFieldString(regData.irisHash),
    merkleRoot: toFieldString(root),
    nullifier: toFieldString(nullifier),
    electionId: toFieldString(electionId),
    hammingThreshold: "123",
    irisCodeLive: liveCode.map((b) => b.toString()),
    irisCodeRegistered: registeredCode.map((b) => b.toString()),
    salt: toFieldString(salt),
    secretKey: toFieldString(regData.secretKey),
    pathElements: pathElements.map(toFieldString),
    pathIndices: pathIndices.map(toFieldString),
  };

  const timings = {};

  const useCpp = fs.existsSync(IRIS_CPP_WITNESS);
  const tmpDir = os.tmpdir();
  const nonce = crypto.randomBytes(8).toString("hex");
  const inputPath = path.join(tmpDir, `bench_iris_input_${nonce}.json`);
  const wtnsPath = path.join(tmpDir, `bench_iris_witness_${nonce}.wtns`);
  const proofPath = path.join(tmpDir, `bench_iris_proof_${nonce}.json`);
  const publicPath = path.join(tmpDir, `bench_iris_public_${nonce}.json`);

  try {
    fs.writeFileSync(inputPath, JSON.stringify(input));

    // Witness generation
    t0 = Date.now();
    if (useCpp) {
      await execFileAsync(IRIS_CPP_WITNESS, [inputPath, wtnsPath]);
    } else {
      await snarkjs.wtns.calculate(input, IRIS_WASM, wtnsPath);
    }
    timings.witnessGen = Date.now() - t0;

    // Proof generation
    const useRapidsnark = fs.existsSync(
      path.join(CIRCUITS_DIR, "rapidsnark", "package", "bin", "prover")
    );

    if (useRapidsnark) {
      const prover = path.join(
        CIRCUITS_DIR,
        "rapidsnark",
        "package",
        "bin",
        "prover"
      );
      t0 = Date.now();
      await execFileAsync(prover, [
        IRIS_ZKEY,
        wtnsPath,
        proofPath,
        publicPath,
      ]);
      timings.proofGen = Date.now() - t0;
      timings.prover = "rapidsnark (C++)";
    } else {
      const wasmBuf = new Uint8Array(fs.readFileSync(IRIS_WASM));
      const zkeyBuf = new Uint8Array(fs.readFileSync(IRIS_ZKEY));
      t0 = Date.now();
      const result = await snarkjs.groth16.fullProve(input, wasmBuf, zkeyBuf);
      timings.proofGen = Date.now() - t0;
      timings.prover = "snarkjs (WASM)";
      fs.writeFileSync(proofPath, JSON.stringify(result.proof));
      fs.writeFileSync(publicPath, JSON.stringify(result.publicSignals));
    }

    // Read proof for size
    const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));

    timings.proofSize = Buffer.byteLength(JSON.stringify(proof));
    timings.publicSignalsCount = publicSignals.length;

    // Verification
    const vkey = JSON.parse(fs.readFileSync(IRIS_VKEY, "utf8"));
    t0 = Date.now();
    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    timings.proofVerify = Date.now() - t0;
    timings.isValid = isValid;
    timings.merkleTime = merkleTime;
    timings.witnessGenerator = useCpp ? "C++ native" : "WASM";
  } finally {
    [inputPath, wtnsPath, proofPath, publicPath].forEach((p) => {
      try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) {}
    });
  }

  return timings;
}

// ============================================================
// Category 3: Storage & Payload Size
// ============================================================

function getStorageMetrics() {
  const metrics = {
    face: {
      wasmSize: fs.statSync(FACE_WASM).size,
      zkeySize: fs.statSync(FACE_ZKEY).size,
      vkeySize: fs.statSync(FACE_VKEY).size,
      r1csSize: fs.statSync(FACE_R1CS).size,
      inputDataDescription: "64 × int64 (scaled floats) = 512 bytes",
      inputElementCount: 64,
      inputBitWidth: "~20 bits per element (scaled ±1M)",
      inputTotalBits: 64 * 20, // approximate
    },
    iris: {
      wasmSize: fs.statSync(IRIS_WASM).size,
      zkeySize: fs.statSync(IRIS_ZKEY).size,
      vkeySize: fs.statSync(IRIS_VKEY).size,
      r1csSize: fs.statSync(IRIS_R1CS).size,
      inputDataDescription: "256 × uint1 (binary bits) = 32 bytes",
      inputElementCount: 256,
      inputBitWidth: "1 bit per element",
      inputTotalBits: 256,
    },
  };

  return metrics;
}

// ============================================================
// Category 4: On-Chain Gas Estimates
// ============================================================

function getGasEstimates() {
  // Groth16 verification gas costs are well-known on Ethereum
  // Source: EIP-197 (bn128 pairing), EIP-196 (bn128 addition/scalar mul)
  //
  // Groth16 verify = 3 pairings + (nPublic + 1) scalar muls + additions
  // Pairing check: 113,000 gas per pair + 80,000 base = ~339,000 + 80,000
  // Scalar mul (bn128): 6,000 gas each
  // Addition (bn128): 150 gas each
  //
  // Face: nPublic = 7 → 8 scalar muls + 8 additions + 1 pairing check(3 pairs)
  //   = 419,000 + 8 × 6,000 + 8 × 150 ≈ 468,200 gas
  //
  // Iris: nPublic = 6 → 7 scalar muls + 7 additions + 1 pairing check(3 pairs)
  //   = 419,000 + 7 × 6,000 + 7 × 150 ≈ 462,050 gas

  const faceVkey = JSON.parse(fs.readFileSync(FACE_VKEY, "utf8"));
  const irisVkey = JSON.parse(fs.readFileSync(IRIS_VKEY, "utf8"));

  const PAIRING_BASE = 45000;  // ecPairing base cost
  const PAIRING_PER_PAIR = 34000;  // ecPairing per pair (post-EIP-1108)
  const SCALAR_MUL = 6000;    // ecMul (post-EIP-1108)
  const ADDITION = 150;        // ecAdd (post-EIP-1108)
  const SSTORE_NEW = 22100;    // SSTORE (new slot)
  const CALLDATA_NONZERO = 16; // per non-zero byte calldata

  // Groth16 verify: 1 pairing check (3 pairs), nPublic+1 scalar muls, nPublic+1 adds
  const faceNPublic = faceVkey.nPublic; // 7
  const irisNPublic = irisVkey.nPublic; // 6

  function calcVerifyGas(nPublic) {
    const pairingGas = PAIRING_BASE + 3 * PAIRING_PER_PAIR; // Fixed 3-pair check
    const scalarMulGas = (nPublic + 1) * SCALAR_MUL;
    const addGas = (nPublic + 1) * ADDITION;
    const overhead = 25000; // Base TX + SLOAD + misc
    return pairingGas + scalarMulGas + addGas + overhead;
  }

  // Proof calldata: pi_a (2×32B), pi_b (2×2×32B), pi_c (2×32B) = 256 bytes
  // Public signals: nPublic × 32 bytes
  function calcCalldataGas(nPublic) {
    const proofBytes = 256; // 8 × 32 bytes
    const signalBytes = nPublic * 32;
    return (proofBytes + signalBytes) * CALLDATA_NONZERO;
  }

  // Nullifier storage (on-chain): 1 SSTORE
  const nullifierStorageGas = SSTORE_NEW;

  // Solidity verifier deployment (estimate from contract size)
  let faceSolSize = 0, irisSolSize = 0;
  if (fs.existsSync(FACE_SOL)) faceSolSize = fs.statSync(FACE_SOL).size;
  if (fs.existsSync(IRIS_SOL)) irisSolSize = fs.statSync(IRIS_SOL).size;

  // Deployment: ~200 gas per byte of bytecode (rough estimate)
  // Solidity ≈ 40% of .sol file size as bytecode
  const faceDeployGas = Math.round(faceSolSize * 0.4 * 200) + 32000;
  const irisDeployGas = Math.round(irisSolSize * 0.4 * 200) + 32000;

  return {
    face: {
      nPublicSignals: faceNPublic,
      verifyGas: calcVerifyGas(faceNPublic),
      calldataGas: calcCalldataGas(faceNPublic),
      nullifierStorageGas,
      totalVoteTxGas: calcVerifyGas(faceNPublic) + calcCalldataGas(faceNPublic) + nullifierStorageGas,
      deployGas: faceDeployGas,
      solFileSize: faceSolSize,
    },
    iris: {
      nPublicSignals: irisNPublic,
      verifyGas: calcVerifyGas(irisNPublic),
      calldataGas: calcCalldataGas(irisNPublic),
      nullifierStorageGas,
      totalVoteTxGas: calcVerifyGas(irisNPublic) + calcCalldataGas(irisNPublic) + nullifierStorageGas,
      deployGas: irisDeployGas,
      solFileSize: irisSolSize,
    },
  };
}

// ============================================================
// Setup: Create test data for both pipelines
// ============================================================

async function setupFaceData() {
  const registeredEmb = generateFakeEmbedding(42);
  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";
  const regData = await faceSnark.computeRegistrationData(
    registeredEmb,
    saltHex
  );

  // Create dummy commitments for Merkle tree
  const commitments = [];
  for (let i = 0; i < NUM_VOTERS - 1; i++) {
    const emb = generateFakeEmbedding(100 + i);
    const embScaled = faceSnark.scaleEmbedding(emb);
    const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
    const fh = await faceSnark.poseidonHashEmbedding(embScaled, s);
    const sk = faceSnark.generateSecretKey();
    const c = await faceSnark.computeCommitment(fh, sk);
    commitments.push(c);
  }
  commitments.push(regData.commitment); // Our voter last

  return { regData, commitments };
}

async function setupIrisData() {
  const registeredCode = generateFakeIrisCode256(42);
  const saltHex = "b1c2d3e4f5a6789012345678abcdef02";
  const salt = BigInt("0x" + saltHex);

  // Compute iris hash manually (matching iris-snark.js logic)
  const irisHash = await irisSnark.poseidonHashIrisCode(registeredCode, salt);
  const secretKey = faceSnark.generateSecretKey();
  const commitment = await irisSnark.computeIrisCommitment(irisHash, secretKey);

  const regData = { irisHash, secretKey, commitment, irisCode256: registeredCode };

  // Create dummy iris commitments for Merkle tree
  const commitments = [];
  for (let i = 0; i < NUM_VOTERS - 1; i++) {
    const code = generateFakeIrisCode256(200 + i);
    const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
    const ih = await irisSnark.poseidonHashIrisCode(code, s);
    const sk = faceSnark.generateSecretKey();
    const c = await irisSnark.computeIrisCommitment(ih, sk);
    commitments.push(c);
  }
  commitments.push(commitment);

  return { regData, commitments };
}

// ============================================================
// Main Benchmark Runner
// ============================================================

async function main() {
  console.log("\n" + "═".repeat(70));
  console.log("  ZKP BIOMETRIC VOTING — PUBLICATION-GRADE BENCHMARK SUITE");
  console.log("  For Q1 Journal Paper: Face vs. Iris ZK-SNARK Comparison");
  console.log("═".repeat(70));
  console.log(`\n⚙️  Configuration:`);
  console.log(`   Timing iterations:  ${NUM_RUNS} (+ ${WARMUP_RUNS} warm-up, discarded)`);
  console.log(`   Outlier trimming:   ${TRIM_PERCENT * 100}% each end (${Math.floor(NUM_RUNS * TRIM_PERCENT)} dropped per side)`);
  console.log(`   Reported metric:    trimmed mean ± σ`);
  console.log(`   Simulated voters:   ${NUM_VOTERS}`);
  console.log(`   Merkle tree depth:  20 levels (1M capacity)`);
  console.log(`   Platform:           ${os.type()} ${os.arch()}`);
  console.log(`   CPU:                ${os.cpus()[0]?.model || "unknown"}`);
  console.log(`   RAM:                ${(os.totalmem() / (1024 ** 3)).toFixed(1)} GB`);
  console.log(`   Node.js:            ${process.version}`);
  console.log(`   Output dir:         ${OUTPUT_DIR}`);
  console.log();
  if (NUM_RUNS < 30) {
    console.log(`   ⚠️  WARNING: ${NUM_RUNS} runs is too few for publication.`);
    console.log(`      Use --runs 100 for paper-quality results.`);
  }

  // ========================================
  // Initialize Poseidon
  // ========================================
  console.log("\n⏳ Initializing Poseidon hash...");
  await faceSnark.initPoseidon();
  await faceSnark.getZeroHashes();
  await irisSnark.getIrisZeroHashes();
  console.log("✅ Poseidon + Zero hashes initialized\n");

  // ========================================
  // CATEGORY 1: Circuit Complexity
  // ========================================
  console.log("━".repeat(70));
  console.log("  CATEGORY 1: CIRCUIT COMPLEXITY (R1CS Analysis)");
  console.log("━".repeat(70));

  const faceR1CS = await getR1CSInfo(FACE_R1CS, "Face (Cosine Similarity)");
  const irisR1CS = await getR1CSInfo(IRIS_R1CS, "Iris (Hamming Distance)");

  console.log(`\n  Face Circuit:`);
  console.log(`    Total R1CS Constraints:  ${faceR1CS.nConstraints.toLocaleString()}`);
  console.log(`    Total Variables:         ${faceR1CS.nVars.toLocaleString()}`);
  console.log(`    Public Inputs:           ${faceR1CS.nPubInputs}`);
  console.log(`    Private Inputs:          ${faceR1CS.nPrvInputs}`);
  console.log(`    Outputs:                 ${faceR1CS.nOutputs}`);

  console.log(`\n  Iris Circuit:`);
  console.log(`    Total R1CS Constraints:  ${irisR1CS.nConstraints.toLocaleString()}`);
  console.log(`    Total Variables:         ${irisR1CS.nVars.toLocaleString()}`);
  console.log(`    Public Inputs:           ${irisR1CS.nPubInputs}`);
  console.log(`    Private Inputs:          ${irisR1CS.nPrvInputs}`);
  console.log(`    Outputs:                 ${irisR1CS.nOutputs}`);

  const constraintRatio = (faceR1CS.nConstraints / irisR1CS.nConstraints).toFixed(1);
  console.log(`\n  ⚡ Constraint Reduction: ${constraintRatio}x (Face/Iris)`);

  // ========================================
  // CATEGORY 3: Storage & Payload Size
  // ========================================
  console.log("\n" + "━".repeat(70));
  console.log("  CATEGORY 3: STORAGE & PAYLOAD SIZE");
  console.log("━".repeat(70));

  const storage = getStorageMetrics();

  console.log(`\n  Face Pipeline:`);
  console.log(`    WASM witness gen:    ${formatBytes(storage.face.wasmSize)}`);
  console.log(`    Proving key (.zkey): ${formatBytes(storage.face.zkeySize)}`);
  console.log(`    Verification key:    ${formatBytes(storage.face.vkeySize)}`);
  console.log(`    R1CS file:           ${formatBytes(storage.face.r1csSize)}`);
  console.log(`    Input data:          ${storage.face.inputDataDescription}`);

  console.log(`\n  Iris Pipeline:`);
  console.log(`    WASM witness gen:    ${formatBytes(storage.iris.wasmSize)}`);
  console.log(`    Proving key (.zkey): ${formatBytes(storage.iris.zkeySize)}`);
  console.log(`    Verification key:    ${formatBytes(storage.iris.vkeySize)}`);
  console.log(`    R1CS file:           ${formatBytes(storage.iris.r1csSize)}`);
  console.log(`    Input data:          ${storage.iris.inputDataDescription}`);

  const zkeyRatio = (storage.face.zkeySize / storage.iris.zkeySize).toFixed(1);
  console.log(`\n  ⚡ Proving Key Reduction: ${zkeyRatio}x (Face/Iris)`);

  // ========================================
  // Setup test data
  // ========================================
  console.log("\n⏳ Setting up test data...");
  const faceSetup = await setupFaceData();
  const irisSetup = await setupIrisData();
  console.log(`✅ Test data ready (${NUM_VOTERS} voters per tree)\n`);

  // ========================================
  // CATEGORY 2: Computational Latency
  // ========================================
  const totalRuns = WARMUP_RUNS + NUM_RUNS;
  console.log("━".repeat(70));
  console.log(`  CATEGORY 2: COMPUTATIONAL LATENCY`);
  console.log(`  ${WARMUP_RUNS} warm-up (discarded) + ${NUM_RUNS} measured iterations`);
  console.log(`  5% trimmed mean ± σ — Reviewer-2-proof methodology`);
  console.log("━".repeat(70));

  const electionId = BigInt("12345");
  const startBench = Date.now();

  // Collect ALL runs (warm-up + measured)
  const faceResults = [];
  const irisResults = [];

  for (let run = 1; run <= totalRuns; run++) {
    const isWarmup = run <= WARMUP_RUNS;
    const label = isWarmup ? `🔥 Warm-up ${run}/${WARMUP_RUNS}` : `📊 Run ${run - WARMUP_RUNS}/${NUM_RUNS}`;

    // Print progress
    if (!isWarmup) {
      const measuredRun = run - WARMUP_RUNS;
      if (measuredRun === 1 || measuredRun % 10 === 0 || measuredRun === NUM_RUNS) {
        const elapsed = ((Date.now() - startBench) / 1000).toFixed(0);
        process.stdout.write(`\r  ${progressBar(measuredRun, NUM_RUNS)} ${elapsed}s elapsed`);
        if (measuredRun === NUM_RUNS) process.stdout.write("\n");
      }
    } else {
      process.stdout.write(`\r  ${label}...`);
      if (run === WARMUP_RUNS) process.stdout.write("\n");
    }

    // Invalidate caches each run for consistent cold measurement
    faceSnark.invalidateMerkleCache();
    irisSnark.invalidateIrisMerkleCache();

    // Interleave Face and Iris to control for thermal throttling:
    // On even runs do Face first, on odd runs do Iris first
    let faceTimings, irisTimings;
    if (run % 2 === 0) {
      faceTimings = await benchmarkFaceProof(faceSetup.regData, faceSetup.commitments, electionId, run);
      irisTimings = await benchmarkIrisProof(irisSetup.regData, irisSetup.commitments, electionId, run);
    } else {
      irisTimings = await benchmarkIrisProof(irisSetup.regData, irisSetup.commitments, electionId, run);
      faceTimings = await benchmarkFaceProof(faceSetup.regData, faceSetup.commitments, electionId, run);
    }

    // Only keep measured runs (discard warm-up)
    if (!isWarmup) {
      faceResults.push(faceTimings);
      irisResults.push(irisTimings);
    }
  }

  const benchDuration = ((Date.now() - startBench) / 1000).toFixed(1);
  console.log(`\n  ✅ ${NUM_RUNS} iterations completed in ${benchDuration}s`);
  console.log(`     ${WARMUP_RUNS} warm-up runs discarded`);
  console.log(`     ${Math.floor(NUM_RUNS * TRIM_PERCENT)} outliers trimmed per side (${TRIM_PERCENT * 100}%)`);
  console.log(`     ${NUM_RUNS - 2 * Math.floor(NUM_RUNS * TRIM_PERCENT)} samples used for trimmed mean\n`);

  // Compute publication-grade statistics with trimmed mean
  const faceStats = {
    witnessGen: computeStats(faceResults.map(r => r.witnessGen)),
    proofGen: computeStats(faceResults.map(r => r.proofGen)),
    proofVerify: computeStats(faceResults.map(r => r.proofVerify)),
    merkleTree: computeStats(faceResults.map(r => r.merkleTime)),
    proofSize: faceResults[0].proofSize,
    prover: faceResults[0].prover,
    witnessGenerator: faceResults[0].witnessGenerator,
  };

  const irisStats = {
    witnessGen: computeStats(irisResults.map(r => r.witnessGen)),
    proofGen: computeStats(irisResults.map(r => r.proofGen)),
    proofVerify: computeStats(irisResults.map(r => r.proofVerify)),
    merkleTree: computeStats(irisResults.map(r => r.merkleTime)),
    proofSize: irisResults[0].proofSize,
    prover: irisResults[0].prover,
    witnessGenerator: irisResults[0].witnessGenerator,
  };

  console.log(`  Face Latency (5% trimmed mean of ${NUM_RUNS} runs):`);
  console.log(`    Witness Generator:   ${faceStats.witnessGenerator}`);
  console.log(`    Prover:              ${faceStats.prover}`);
  console.log(`    Witness Generation:  ${formatPaperMs(faceStats.witnessGen)}`);
  console.log(`    Proof Generation:    ${formatPaperMs(faceStats.proofGen)}`);
  console.log(`    Proof Verification:  ${formatPaperMs(faceStats.proofVerify)}`);
  console.log(`    Total E2E:           ${formatMs(faceStats.witnessGen.trimmedMean + faceStats.proofGen.trimmedMean + faceStats.proofVerify.trimmedMean)}`);
  console.log(`    Proof Payload:       ${formatBytes(faceStats.proofSize)}`);
  console.log(`    Range:               [${faceStats.proofGen.min}ms .. ${faceStats.proofGen.max}ms]`);

  console.log(`\n  Iris Latency (5% trimmed mean of ${NUM_RUNS} runs):`);
  console.log(`    Witness Generator:   ${irisStats.witnessGenerator}`);
  console.log(`    Prover:              ${irisStats.prover}`);
  console.log(`    Witness Generation:  ${formatPaperMs(irisStats.witnessGen)}`);
  console.log(`    Proof Generation:    ${formatPaperMs(irisStats.proofGen)}`);
  console.log(`    Proof Verification:  ${formatPaperMs(irisStats.proofVerify)}`);
  console.log(`    Total E2E:           ${formatMs(irisStats.witnessGen.trimmedMean + irisStats.proofGen.trimmedMean + irisStats.proofVerify.trimmedMean)}`);
  console.log(`    Proof Payload:       ${formatBytes(irisStats.proofSize)}`);
  console.log(`    Range:               [${irisStats.proofGen.min}ms .. ${irisStats.proofGen.max}ms]`);

  const proofSpeedup = (faceStats.proofGen.trimmedMean / irisStats.proofGen.trimmedMean).toFixed(1);
  const witnessSpeedup = (faceStats.witnessGen.trimmedMean / irisStats.witnessGen.trimmedMean).toFixed(1);
  const totalSpeedup = ((faceStats.witnessGen.trimmedMean + faceStats.proofGen.trimmedMean) / (irisStats.witnessGen.trimmedMean + irisStats.proofGen.trimmedMean)).toFixed(1);
  console.log(`\n  ⚡ Witness Gen Speedup:  ${witnessSpeedup}x (Face/Iris)`);
  console.log(`  ⚡ Proof Gen Speedup:    ${proofSpeedup}x (Face/Iris)`);
  console.log(`  ⚡ Total Prover Speedup: ${totalSpeedup}x (Face/Iris)`);

  // ========================================
  // CATEGORY 4: On-Chain Gas Estimates
  // ========================================
  console.log("\n" + "━".repeat(70));
  console.log("  CATEGORY 4: ON-CHAIN GAS ESTIMATES (Ethereum EIP-1108)");
  console.log("━".repeat(70));

  const gas = getGasEstimates();

  console.log(`\n  Face On-Chain:`);
  console.log(`    Public signals:       ${gas.face.nPublicSignals}`);
  console.log(`    Verify proof gas:     ${gas.face.verifyGas.toLocaleString()}`);
  console.log(`    Calldata gas:         ${gas.face.calldataGas.toLocaleString()}`);
  console.log(`    Nullifier storage:    ${gas.face.nullifierStorageGas.toLocaleString()}`);
  console.log(`    Total vote TX gas:    ${gas.face.totalVoteTxGas.toLocaleString()}`);
  console.log(`    Verifier deploy gas:  ~${gas.face.deployGas.toLocaleString()}`);

  console.log(`\n  Iris On-Chain:`);
  console.log(`    Public signals:       ${gas.iris.nPublicSignals}`);
  console.log(`    Verify proof gas:     ${gas.iris.verifyGas.toLocaleString()}`);
  console.log(`    Calldata gas:         ${gas.iris.calldataGas.toLocaleString()}`);
  console.log(`    Nullifier storage:    ${gas.iris.nullifierStorageGas.toLocaleString()}`);
  console.log(`    Total vote TX gas:    ${gas.iris.totalVoteTxGas.toLocaleString()}`);
  console.log(`    Verifier deploy gas:  ~${gas.iris.deployGas.toLocaleString()}`);

  const gasRatio = (gas.face.totalVoteTxGas / gas.iris.totalVoteTxGas).toFixed(2);
  console.log(`\n  ⚡ Gas Ratio: ${gasRatio}x (Face/Iris) — Groth16 is O(1), difference from public signals only`);

  // ========================================
  // PUBLICATION-READY TABLES
  // ========================================
  console.log("\n\n" + "═".repeat(70));
  console.log("  📝 TABLE 1: THE CRYPTOGRAPHIC SHOWDOWN");
  console.log("═".repeat(70));
  console.log();

  const table1 = [
    ["Metric", "Face (Cosine Similarity)", "Iris (Hamming Distance)", "Factor"],
    ["─".repeat(30), "─".repeat(26), "─".repeat(26), "─".repeat(12)],
    ["Data Format", "64 × int (scaled float)", "256 × uint1 (binary)", "—"],
    ["Biometric Input Size", `${64 * 8} bytes (64 × int64)`, "32 bytes (256 bits)", `${(64 * 8 / 32).toFixed(0)}x`],
    ["Similarity Metric", "Squared Cosine (≥0.25)", "Hamming Distance (<123)", "—"],
    ["Math Operation", "dot², norm², GreaterEqThan(128)", "XOR, accumulate, LessThan(9)", "—"],
    ["R1CS Constraints", faceR1CS.nConstraints.toLocaleString(), irisR1CS.nConstraints.toLocaleString(), `${constraintRatio}x`],
    ["Circuit Variables", faceR1CS.nVars.toLocaleString(), irisR1CS.nVars.toLocaleString(), `${(faceR1CS.nVars / irisR1CS.nVars).toFixed(1)}x`],
    ["Public Signals", `${faceR1CS.nPubInputs + faceR1CS.nOutputs}`, `${irisR1CS.nPubInputs + irisR1CS.nOutputs}`, "—"],
    ["Proving Key (.zkey)", formatBytes(storage.face.zkeySize), formatBytes(storage.iris.zkeySize), `${zkeyRatio}x`],
    ["WASM Witness Gen", formatBytes(storage.face.wasmSize), formatBytes(storage.iris.wasmSize), `${(storage.face.wasmSize / storage.iris.wasmSize).toFixed(1)}x`],
    ["Verification Key", formatBytes(storage.face.vkeySize), formatBytes(storage.iris.vkeySize), "~1x"],
    ["Witness Gen Time", `${formatMs(faceStats.witnessGen.trimmedMean)} ±${faceStats.witnessGen.trimmedStd.toFixed(0)}ms`, `${formatMs(irisStats.witnessGen.trimmedMean)} ±${irisStats.witnessGen.trimmedStd.toFixed(0)}ms`, `${witnessSpeedup}x`],
    ["Proof Gen Time", `${formatMs(faceStats.proofGen.trimmedMean)} ±${faceStats.proofGen.trimmedStd.toFixed(0)}ms`, `${formatMs(irisStats.proofGen.trimmedMean)} ±${irisStats.proofGen.trimmedStd.toFixed(0)}ms`, `${proofSpeedup}x`],
    ["Proof Verify Time", `${formatMs(faceStats.proofVerify.trimmedMean)} ±${faceStats.proofVerify.trimmedStd.toFixed(0)}ms`, `${formatMs(irisStats.proofVerify.trimmedMean)} ±${irisStats.proofVerify.trimmedStd.toFixed(0)}ms`, `${(faceStats.proofVerify.trimmedMean / irisStats.proofVerify.trimmedMean).toFixed(1)}x`],
    ["Total Prover Time", formatMs(faceStats.witnessGen.trimmedMean + faceStats.proofGen.trimmedMean), formatMs(irisStats.witnessGen.trimmedMean + irisStats.proofGen.trimmedMean), `${totalSpeedup}x`],
    ["Proof Payload Size", formatBytes(faceStats.proofSize), formatBytes(irisStats.proofSize), "~1x (Groth16 O(1))"],
    ["Merkle Tree Depth", "20 levels", "20 levels", "1x"],
    ["Anonymity Set", "2²⁰ ≈ 1M voters", "2²⁰ ≈ 1M voters", "1x"],
  ];

  // Print formatted table
  const colWidths = [30, 28, 28, 20];
  for (const row of table1) {
    const formatted = row.map((cell, i) => String(cell).padEnd(colWidths[i])).join("│ ");
    console.log(`  ${formatted}`);
  }

  console.log("\n\n" + "═".repeat(70));
  console.log("  📝 TABLE 2: SMART CONTRACT & GAS COSTS");
  console.log("═".repeat(70));
  console.log();

  const table2 = [
    ["Metric", "Face", "Iris", "Difference"],
    ["─".repeat(30), "─".repeat(20), "─".repeat(20), "─".repeat(15)],
    ["Public Signals Count", gas.face.nPublicSignals.toString(), gas.iris.nPublicSignals.toString(), `${gas.face.nPublicSignals - gas.iris.nPublicSignals} more`],
    ["Proof Verification Gas", gas.face.verifyGas.toLocaleString(), gas.iris.verifyGas.toLocaleString(), `${(gas.face.verifyGas - gas.iris.verifyGas).toLocaleString()}`],
    ["Calldata Gas", gas.face.calldataGas.toLocaleString(), gas.iris.calldataGas.toLocaleString(), `${(gas.face.calldataGas - gas.iris.calldataGas).toLocaleString()}`],
    ["Nullifier Registry (SSTORE)", gas.face.nullifierStorageGas.toLocaleString(), gas.iris.nullifierStorageGas.toLocaleString(), "identical"],
    ["Total Vote TX Gas", gas.face.totalVoteTxGas.toLocaleString(), gas.iris.totalVoteTxGas.toLocaleString(), `${gasRatio}x`],
    ["Verifier Deploy Gas", `~${gas.face.deployGas.toLocaleString()}`, `~${gas.iris.deployGas.toLocaleString()}`, "—"],
    ["Verifier Contract Size", formatBytes(gas.face.solFileSize), formatBytes(gas.iris.solFileSize), "—"],
    ["Vote Cost @ 30 gwei", `$${((gas.face.totalVoteTxGas * 30 * 3000) / 1e18).toFixed(2)}`, `$${((gas.iris.totalVoteTxGas * 30 * 3000) / 1e18).toFixed(2)}`, "—"],
  ];

  const colWidths2 = [30, 22, 22, 18];
  for (const row of table2) {
    const formatted = row.map((cell, i) => String(cell).padEnd(colWidths2[i])).join("│ ");
    console.log(`  ${formatted}`);
  }

  // ========================================
  // Figure data (JSON export)
  // ========================================
  console.log("\n\n" + "═".repeat(70));
  console.log("  📊 FIGURE DATA (for plotting)");
  console.log("═".repeat(70));

  const figureData = {
    metadata: {
      timestamp: new Date().toISOString(),
      platform: `${os.type()} ${os.arch()}`,
      cpu: os.cpus()[0]?.model || "unknown",
      ram_gb: parseFloat((os.totalmem() / (1024 ** 3)).toFixed(1)),
      node_version: process.version,
      num_runs: NUM_RUNS,
      num_voters: NUM_VOTERS,
      merkle_depth: 20,
      face_witness_gen: faceStats.witnessGenerator,
      iris_witness_gen: irisStats.witnessGenerator,
      prover: faceStats.prover,
    },

    // Figure 1: Proving Time vs Constraints (grouped bar chart)
    figure1_constraints_and_time: {
      labels: ["Face (Cosine)", "Iris (Hamming)"],
      r1cs_constraints: [faceR1CS.nConstraints, irisR1CS.nConstraints],
      witness_gen_ms: [faceStats.witnessGen.trimmedMean, irisStats.witnessGen.trimmedMean],
      proof_gen_ms: [faceStats.proofGen.trimmedMean, irisStats.proofGen.trimmedMean],
      proof_verify_ms: [faceStats.proofVerify.trimmedMean, irisStats.proofVerify.trimmedMean],
      total_prover_ms: [
        faceStats.witnessGen.trimmedMean + faceStats.proofGen.trimmedMean,
        irisStats.witnessGen.trimmedMean + irisStats.proofGen.trimmedMean,
      ],
    },

    // Figure 2: Storage comparison (stacked bar)
    figure2_storage: {
      labels: ["Face (Cosine)", "Iris (Hamming)"],
      zkey_bytes: [storage.face.zkeySize, storage.iris.zkeySize],
      wasm_bytes: [storage.face.wasmSize, storage.iris.wasmSize],
      vkey_bytes: [storage.face.vkeySize, storage.iris.vkeySize],
      r1cs_bytes: [storage.face.r1csSize, storage.iris.r1csSize],
      proof_bytes: [faceStats.proofSize, irisStats.proofSize],
    },

    // Figure 3: Gas breakdown (stacked bar)
    figure3_gas: {
      labels: ["Face (Cosine)", "Iris (Hamming)"],
      verify_gas: [gas.face.verifyGas, gas.iris.verifyGas],
      calldata_gas: [gas.face.calldataGas, gas.iris.calldataGas],
      nullifier_gas: [gas.face.nullifierStorageGas, gas.iris.nullifierStorageGas],
      total_gas: [gas.face.totalVoteTxGas, gas.iris.totalVoteTxGas],
    },

    // Raw per-run data for error bars
    raw_runs: {
      face: {
        witness_gen_ms: faceStats.witnessGen.raw,
        proof_gen_ms: faceStats.proofGen.raw,
        proof_verify_ms: faceStats.proofVerify.raw,
      },
      iris: {
        witness_gen_ms: irisStats.witnessGen.raw,
        proof_gen_ms: irisStats.proofGen.raw,
        proof_verify_ms: irisStats.proofVerify.raw,
      },
    },

    // Table 1 summary
    table1_summary: {
      face_constraints: faceR1CS.nConstraints,
      iris_constraints: irisR1CS.nConstraints,
      constraint_ratio: parseFloat(constraintRatio),
      face_zkey_mb: parseFloat((storage.face.zkeySize / (1024 * 1024)).toFixed(2)),
      iris_zkey_mb: parseFloat((storage.iris.zkeySize / (1024 * 1024)).toFixed(2)),
      zkey_ratio: parseFloat(zkeyRatio),
      face_witness_ms: faceStats.witnessGen.trimmedMean,
      iris_witness_ms: irisStats.witnessGen.trimmedMean,
      witness_speedup: parseFloat(witnessSpeedup),
      face_proof_ms: faceStats.proofGen.trimmedMean,
      iris_proof_ms: irisStats.proofGen.trimmedMean,
      proof_speedup: parseFloat(proofSpeedup),
      total_speedup: parseFloat(totalSpeedup),
      face_verify_ms: faceStats.proofVerify.trimmedMean,
      iris_verify_ms: irisStats.proofVerify.trimmedMean,
      face_proof_bytes: faceStats.proofSize,
      iris_proof_bytes: irisStats.proofSize,
    },

    // Table 2 summary
    table2_summary: {
      face_verify_gas: gas.face.verifyGas,
      iris_verify_gas: gas.iris.verifyGas,
      face_total_gas: gas.face.totalVoteTxGas,
      iris_total_gas: gas.iris.totalVoteTxGas,
      gas_ratio: parseFloat(gasRatio),
    },
  };

  // Save JSON to compareBenchmarks/ folder
  const jsonPath = path.join(OUTPUT_DIR, "benchmark_results.json");
  fs.writeFileSync(jsonPath, JSON.stringify(figureData, null, 2));
  console.log(`\n  ✅ Full results saved to: ${jsonPath}`);

  // Print the JSON if requested
  if (JSON_OUTPUT) {
    console.log("\n" + JSON.stringify(figureData, null, 2));
  }

  // ========================================
  // Final Summary
  // ========================================
  console.log("\n\n" + "═".repeat(70));
  console.log("  🏆 KEY FINDINGS FOR PAPER NARRATIVE");
  console.log("═".repeat(70));
  console.log(`
  1. CIRCUIT COMPLEXITY:
     Iris uses ${irisR1CS.nConstraints.toLocaleString()} R1CS constraints vs Face's ${faceR1CS.nConstraints.toLocaleString()}
     → ${constraintRatio}x reduction from discrete (XOR) vs continuous (dot product) math

  2. PROVER PERFORMANCE:
     Iris total prover time: ${formatMs(irisStats.witnessGen.trimmedMean + irisStats.proofGen.trimmedMean)}
     Face total prover time: ${formatMs(faceStats.witnessGen.trimmedMean + faceStats.proofGen.trimmedMean)}
     → ${totalSpeedup}x faster proving with iris biometrics

  3. MOBILE FEASIBILITY:
     Iris proving key (.zkey): ${formatBytes(storage.iris.zkeySize)} — practical for mobile download
     Face proving key (.zkey): ${formatBytes(storage.face.zkeySize)} — ${zkeyRatio}x larger

  4. ON-CHAIN COST:
     Groth16 verification is O(1) — gas costs are nearly identical
     (${gasRatio}x ratio comes only from ${gas.face.nPublicSignals - gas.iris.nPublicSignals} extra public signals in face)
     This shifts the bottleneck entirely to the PROVER side

  5. PROOF SIZE:
     Both produce ~${formatBytes(faceStats.proofSize)} proofs (Groth16 magic — O(1) proof size)
     → Verification cost is the same regardless of circuit complexity
`);
  console.log("═".repeat(70));
  console.log("  Benchmark complete. Use benchmark_results.json for plotting.");
  console.log("═".repeat(70) + "\n");
}

main().catch((err) => {
  console.error("\n❌ BENCHMARK FATAL ERROR:", err);
  process.exit(1);
});
