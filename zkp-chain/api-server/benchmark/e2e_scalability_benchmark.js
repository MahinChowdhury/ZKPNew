/**
 * Parametric E2E Scalability Benchmark — DUAL MODALITY
 * Architecture: ZK-SNARK (Groth16) + Merkle Tree + Nullifier
 *
 * Sweeps two independent dimensions for BOTH Face and Iris pipelines:
 *   Dim 1: Merkle tree size (voters) → shows Poseidon tree scaling
 *   Dim 2: Candidate count          → shows O(C) ElGamal/ZKP scaling
 *
 * Run:
 *   node benchmark/e2e_scalability_benchmark.js
 *   node benchmark/e2e_scalability_benchmark.js --iters 5
 */

"use strict";

const crypto      = require("crypto");
const fs          = require("fs");
const os          = require("os");
const path        = require("path");
const snark       = require("../crypto/snark");
const irisSnark   = require("../crypto/iris-snark");
const homomorphic = require("../crypto/homomorphic");

// ─── CLI ──────────────────────────────────────────────────────────────────────
const args   = process.argv.slice(2);
const getArg = (f, d) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : d; };
const ITERS  = parseInt(getArg("--iters", "10"), 10);

// ─── Sweep dimensions ─────────────────────────────────────────────────────────
// Dim 1: Merkle tree voter counts
const VOTER_COUNTS     = [2, 5, 10, 25, 50, 100];
// Dim 2: Candidate counts (ElGamal/ZKP scalability)
const CANDIDATE_COUNTS = [2, 3, 5, 10, 20];

// ─── Helpers ──────────────────────────────────────────────────────────────────
function nowMs() { return Number(process.hrtime.bigint()) / 1e6; }
function sha256Hash(d) { return crypto.createHash("sha256").update(String(d)).digest("hex"); }
function calcStats(arr) {
  const s    = [...arr].sort((a, b) => a - b);
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const sd   = Math.sqrt(arr.reduce((a, v) => a + (v - mean) ** 2, 0) / arr.length);
  const trim = Math.floor(s.length * 0.05);
  const trimmed = s.slice(trim, s.length - trim);
  const tMean = trimmed.length > 0 ? trimmed.reduce((a, b) => a + b, 0) / trimmed.length : mean;
  const tSd = trimmed.length > 0
    ? Math.sqrt(trimmed.reduce((a, v) => a + (v - tMean) ** 2, 0) / trimmed.length) : sd;
  return {
    mean: +mean.toFixed(3), sd: +sd.toFixed(3),
    min:  +s[0].toFixed(3), max: +s[s.length - 1].toFixed(3),
    p95:  +s[Math.ceil(0.95 * s.length) - 1].toFixed(3),
    trimmedMean: +tMean.toFixed(3), trimmedSd: +tSd.toFixed(3),
  };
}
function suppress(fn) {
  const o = { log: console.log, error: console.error, warn: console.warn };
  console.log = console.error = console.warn = () => {};
  try { return fn(); } finally { Object.assign(console, o); }
}
async function suppressAsync(fn) {
  const o = { log: console.log, error: console.error, warn: console.warn };
  console.log = console.error = console.warn = () => {};
  try { return await fn(); } finally { Object.assign(console, o); }
}

const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toFieldString(val) {
  let v = BigInt(val);
  if (v < 0n) v = (v % BN128_PRIME) + BN128_PRIME;
  return (v % BN128_PRIME).toString();
}

// ─── Fake data generators ─────────────────────────────────────────────────────
function generateFakeEmbedding(seed = 42) {
  const emb = new Array(64); let state = seed;
  for (let i = 0; i < 64; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    emb[i] = (state / 0x7fffffff) * 2 - 1;
  }
  const norm = Math.sqrt(emb.reduce((s, v) => s + v * v, 0));
  return emb.map(v => v / norm);
}

function addFaceNoise(emb, noise = 0.05) {
  const noisy = emb.map(v => v + (Math.random() - 0.5) * noise);
  const norm = Math.sqrt(noisy.reduce((s, v) => s + v * v, 0));
  return noisy.map(v => v / norm);
}

function generateFakeIrisCode256(seed = 42) {
  const code = new Array(256); let state = seed;
  for (let i = 0; i < 256; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    code[i] = state % 2;
  }
  return code;
}

function addIrisNoise(code, flipRate = 0.10) {
  return code.map(bit => (Math.random() < flipRate ? 1 - bit : bit));
}

// ─── Build commitments pool of size N (face) ──────────────────────────────────
async function buildFaceCommitmentsPool(N, regData) {
  const commitments = [];
  for (let i = 0; i < N - 1; i++) {
    const emb = generateFakeEmbedding(100 + i);
    const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
    const fh = await suppressAsync(() => snark.poseidonHashEmbedding(snark.scaleEmbedding(emb), s));
    const sk = snark.generateSecretKey();
    const c  = await suppressAsync(() => snark.computeCommitment(fh, sk));
    commitments.push(c);
  }
  commitments.push(regData.commitment);
  return commitments;
}

// ─── Build commitments pool of size N (iris) ──────────────────────────────────
async function buildIrisCommitmentsPool(N, irisHash, secretKey, commitment) {
  const commitments = [];
  for (let i = 0; i < N - 1; i++) {
    const code = generateFakeIrisCode256(200 + i);
    const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
    const ih = await suppressAsync(() => irisSnark.poseidonHashIrisCode(code, s));
    const sk = snark.generateSecretKey();
    const c  = await suppressAsync(() => irisSnark.computeIrisCommitment(ih, sk));
    commitments.push(c);
  }
  commitments.push(commitment);
  return commitments;
}

// ============================================================
// MAIN
// ============================================================
(async () => {
  console.log("\n" + "=".repeat(70));
  console.log("  ZKP Voting — Scalability Benchmark [DUAL MODALITY]");
  console.log("  Architecture: ZK-SNARK (Groth16) + Merkle Tree + Nullifier");
  console.log("=".repeat(70));
  console.log(`  Iterations per config : ${ITERS}`);
  console.log(`  Voter counts          : [${VOTER_COUNTS}]`);
  console.log(`  Candidate counts      : [${CANDIDATE_COUNTS}]`);
  console.log(`  Platform              : ${os.type()} ${os.arch()}`);
  console.log(`  CPU                   : ${os.cpus()[0]?.model || "unknown"}`);

  // ── Initialize ─────────────────────────────────────────────────────────
  console.log("\n⏳ Initializing Poseidon...");
  await snark.initPoseidon();
  await snark.getZeroHashes();
  await irisSnark.getIrisZeroHashes();
  console.log("✅ Poseidon ready\n");

  // ── Prepare registration data ──────────────────────────────────────────
  const FACE_SALT = "a1b2c3d4e5f6789012345678abcdef01";
  const faceEmbReg = generateFakeEmbedding(42);
  const faceRegData = await suppressAsync(() =>
    snark.computeRegistrationData(faceEmbReg, FACE_SALT)
  );

  const IRIS_SALT = "b1c2d3e4f5a6789012345678abcdef02";
  const irisCodeReg = generateFakeIrisCode256(42);
  const irisSaltBig = BigInt("0x" + IRIS_SALT);
  const irisHash = await suppressAsync(() => irisSnark.poseidonHashIrisCode(irisCodeReg, irisSaltBig));
  const irisSecretKey = snark.generateSecretKey();
  const irisCommitment = await suppressAsync(() => irisSnark.computeIrisCommitment(irisHash, irisSecretKey));

  const electionId = BigInt("12345");
  const elgamalKp = suppress(() => homomorphic.generateKeypair());

  // ─── DIM 1: Merkle Tree Size Sweep ────────────────────────────────────────
  console.log("─".repeat(70));
  console.log("  DIM 1: ZK-SNARK E2E Latency vs Merkle Tree Size (voters)");
  console.log("  Fixed: candidates=3");
  console.log("─".repeat(70));

  const voterSweep = [];

  for (const N of VOTER_COUNTS) {
    console.log(`\n  Building pools for N=${N}...`);

    // Build commitment pools
    const faceComms = await buildFaceCommitmentsPool(N, faceRegData);
    const irisComms = await buildIrisCommitmentsPool(N, irisHash, irisSecretKey, irisCommitment);

    const face_merkle_times = [], face_prove_times = [], face_verify_times = [], face_total_times = [];
    const iris_merkle_times = [], iris_prove_times = [], iris_verify_times = [], iris_total_times = [];

    for (let iter = 0; iter < ITERS; iter++) {
      // ── FACE ──────────────────────────────────────────────
      snark.invalidateMerkleCache();
      const liveEmb = addFaceNoise(faceEmbReg, 0.05);
      const liveScaled = snark.scaleEmbedding(liveEmb);
      const regScaled  = snark.scaleEmbedding(faceEmbReg);

      let t0 = nowMs();
      const { root: fRoot, layers: fLayers, zeroHashes: fZero } = await suppressAsync(() =>
        snark.buildMerkleTreeOptimized(faceComms)
      );
      face_merkle_times.push(nowMs() - t0);

      const fCommit = await suppressAsync(() =>
        snark.computeCommitment(faceRegData.faceHash, faceRegData.secretKey)
      );
      const fIdx = faceComms.findIndex(c => c === fCommit);
      const { pathElements: fPE, pathIndices: fPI } = snark.getMerkleProofOptimized(fLayers, fZero, fIdx);
      const fNullifier = await suppressAsync(() => snark.computeNullifier(faceRegData.secretKey, electionId));

      t0 = nowMs();
      const { proof: fProof, publicSignals: fPub } = await suppressAsync(() =>
        snark.generateProof(
          liveScaled, regScaled, BigInt("0x" + FACE_SALT),
          faceRegData.secretKey, faceRegData.faceHash,
          fRoot, fPE, fPI, electionId, fNullifier, 25n, 100n
        )
      );
      face_prove_times.push(nowMs() - t0);

      t0 = nowMs();
      await suppressAsync(() => snark.verifyProof(fProof, fPub));
      face_verify_times.push(nowMs() - t0);

      face_total_times.push(
        face_merkle_times[iter] + face_prove_times[iter] + face_verify_times[iter]
      );

      // ── IRIS ──────────────────────────────────────────────
      irisSnark.invalidateIrisMerkleCache();
      const liveIris = addIrisNoise(irisCodeReg, 0.10);

      t0 = nowMs();
      const { root: iRoot, layers: iLayers, zeroHashes: iZero } = await suppressAsync(() =>
        irisSnark.buildIrisMerkleTree(irisComms)
      );
      iris_merkle_times.push(nowMs() - t0);

      const iCommit = await suppressAsync(() =>
        irisSnark.computeIrisCommitment(irisHash, irisSecretKey)
      );
      const iIdx = irisComms.findIndex(c => c === iCommit);
      const { pathElements: iPE, pathIndices: iPI } = irisSnark.getIrisMerkleProof(iLayers, iZero, iIdx);
      const iNullifier = await suppressAsync(() => irisSnark.computeIrisNullifier(irisSecretKey, electionId));

      t0 = nowMs();
      const { proof: iProof, publicSignals: iPub } = await suppressAsync(() =>
        irisSnark.generateIrisProof(
          liveIris, irisCodeReg, irisSaltBig,
          irisSecretKey, irisHash,
          iRoot, iPE, iPI, electionId, iNullifier,
          irisSnark.HAMMING_THRESHOLD
        )
      );
      iris_prove_times.push(nowMs() - t0);

      t0 = nowMs();
      await suppressAsync(() => irisSnark.verifyIrisProof(iProof, iPub));
      iris_verify_times.push(nowMs() - t0);

      iris_total_times.push(
        iris_merkle_times[iter] + iris_prove_times[iter] + iris_verify_times[iter]
      );
    }

    const row = {
      voters: N,
      face: {
        merkle_build: calcStats(face_merkle_times),
        snark_prove:  calcStats(face_prove_times),
        snark_verify: calcStats(face_verify_times),
        total_crypto: calcStats(face_total_times),
      },
      iris: {
        merkle_build: calcStats(iris_merkle_times),
        snark_prove:  calcStats(iris_prove_times),
        snark_verify: calcStats(iris_verify_times),
        total_crypto: calcStats(iris_total_times),
      },
    };
    voterSweep.push(row);

    console.log(`  N=${String(N).padEnd(4)} Face: tree=${row.face.merkle_build.trimmedMean}ms prove=${row.face.snark_prove.trimmedMean}ms total=${row.face.total_crypto.trimmedMean}ms`);
    console.log(`  ${" ".repeat(5)} Iris: tree=${row.iris.merkle_build.trimmedMean}ms prove=${row.iris.snark_prove.trimmedMean}ms total=${row.iris.total_crypto.trimmedMean}ms`);
  }

  // ─── DIM 2: Candidate Count Sweep ─────────────────────────────────────────
  console.log("\n" + "─".repeat(70));
  console.log("  DIM 2: ElGamal+ZKP Scalability vs Candidate Count");
  console.log("  Fixed: voters=10");
  console.log("─".repeat(70));

  const candidateSweep = [];

  for (const C of CANDIDATE_COUNTS) {
    const enc_times = [];

    for (let iter = 0; iter < ITERS; iter++) {
      const t0 = nowMs();
      suppress(() => {
        for (let i = 0; i < C; i++) {
          const voteVal = i === 0 ? 1 : 0;
          const cipher = homomorphic.encrypt(elgamalKp.publicKey, voteVal);
          const proof  = homomorphic.proveValidVote(elgamalKp.publicKey, cipher, voteVal, cipher.r);
          const ser    = homomorphic.serializeCiphertext(cipher);
          ser.validityProof = proof;
        }
      });
      enc_times.push(nowMs() - t0);
    }

    const row = {
      candidates: C,
      elgamal_zkp: calcStats(enc_times),
    };
    candidateSweep.push(row);
    console.log(`  C=${String(C).padEnd(2)}  Encrypt+ZKP=${row.elgamal_zkp.trimmedMean}ms ±${row.elgamal_zkp.trimmedSd}ms`);
  }

  // ─── Save results ─────────────────────────────────────────────────────────
  const results = {
    meta: {
      date:        new Date().toISOString(),
      platform:    `${os.type()} ${os.arch()}`,
      cpu:         os.cpus()[0]?.model || "unknown",
      node:        process.version,
      iterations:  ITERS,
      architecture: "ZK-SNARK (Groth16) + Merkle Tree + Nullifier",
    },
    dim1_voter_sweep:     voterSweep,
    dim2_candidate_sweep: candidateSweep,
  };

  const outPath = path.join(__dirname, "e2e_scalability_results.json");
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));

  console.log("\n" + "=".repeat(70));
  console.log(`  ✓ Saved ${outPath}`);
  console.log("  → Run: python benchmark/e2e_scalability_plot.py");
  console.log("=".repeat(70) + "\n");
})();
