/**
 * Comprehensive ZK-SNARK Benchmark Suite — DUAL MODALITY
 * Architecture: ZK-SNARK (Groth16) + Poseidon Merkle Tree + Nullifier
 *
 * Generates data for Figures 1–7 (publication-ready):
 *   Fig 1 — SNARK Prove & Verify Latency (Face vs Iris)
 *   Fig 2 — R1CS Constraints & Proof Generation Complexity
 *   Fig 3 — Throughput: Proofs per Second
 *   Fig 4 — Proof, Key & Artifact Size Comparison
 *   Fig 5 — Nullifier Double-Vote Detection Accuracy
 *   Fig 6 — Merkle Tree Build Scalability vs Voter Count
 *   Fig 7 — System Overview (composite)
 *
 * Run:
 *   node benchmark/zksnark_benchmark.js [--iters N]
 *   Default: 100 iterations (publication-grade)
 */

"use strict";

const crypto    = require("crypto");
const fs        = require("fs");
const os        = require("os");
const path      = require("path");
const snark     = require("../crypto/snark");
const irisSnark = require("../crypto/iris-snark");

// ─── CLI ──────────────────────────────────────────────────────────────────────
const args   = process.argv.slice(2);
const getArg = (f, d) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : d; };
const ITERS  = parseInt(getArg("--iters", "100"), 10);
const WARMUP = 3;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function nowMs() { return Number(process.hrtime.bigint()) / 1e6; }

function calcStats(arr) {
  if (!arr.length) return { mean:0, sd:0, min:0, max:0, p95:0, p99:0, trimmedMean:0, trimmedSd:0, raw: arr };
  const s = [...arr].sort((a, b) => a - b);
  const mean = arr.reduce((a,b) => a+b, 0) / arr.length;
  const sd   = Math.sqrt(arr.reduce((a,v) => a + (v-mean)**2, 0) / arr.length);
  const trim = Math.floor(s.length * 0.05);
  const trimmed = s.slice(trim, s.length - trim);
  const tMean = trimmed.length > 0 ? trimmed.reduce((a,b) => a+b, 0) / trimmed.length : mean;
  const tSd   = trimmed.length > 0
    ? Math.sqrt(trimmed.reduce((a,v) => a + (v-tMean)**2, 0) / trimmed.length) : sd;
  return {
    mean: +mean.toFixed(4), sd: +sd.toFixed(4),
    min:  +s[0].toFixed(4), max: +s[s.length-1].toFixed(4),
    p95:  +s[Math.ceil(0.95*s.length)-1].toFixed(4),
    p99:  +s[Math.ceil(0.99*s.length)-1].toFixed(4),
    trimmedMean: +tMean.toFixed(4), trimmedSd: +tSd.toFixed(4),
    raw: arr.map(v => +v.toFixed(4)),
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

// ─── Synthetic data generators ────────────────────────────────────────────────
function generateFakeEmbedding(seed = 42) {
  const emb = new Array(64); let state = seed;
  for (let i = 0; i < 64; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    emb[i] = (state / 0x7fffffff) * 2 - 1;
  }
  const norm = Math.sqrt(emb.reduce((s,v) => s + v*v, 0));
  return emb.map(v => v/norm);
}
function addFaceNoise(emb, noise = 0.05) {
  const noisy = emb.map(v => v + (Math.random()-0.5)*noise);
  const norm = Math.sqrt(noisy.reduce((s,v) => s + v*v, 0));
  return noisy.map(v => v/norm);
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

// ─── File size helper ─────────────────────────────────────────────────────────
function fileSizeKB(p) {
  try { return +(fs.statSync(p).size / 1024).toFixed(2); } catch { return 0; }
}
function fileSizeMB(p) {
  try { return +(fs.statSync(p).size / (1024*1024)).toFixed(4); } catch { return 0; }
}

// ─── R1CS constraint count parser ─────────────────────────────────────────────
function getR1CSConstraintCount(r1csPath) {
  try {
    const buf = fs.readFileSync(r1csPath);
    // r1cs binary format: magic (4) + version (4) + nSections (4)
    // Section type 1 (header): fieldSize, prime, nWires, nPubOutputs, nPubInputs, nPrivInputs, nLabels, nConstraints
    // We parse the header section to find nConstraints
    let offset = 12; // skip magic + version + nSections
    while (offset < buf.length) {
      const sectionType = buf.readUInt32LE(offset); offset += 4;
      const sectionSizeLow = buf.readUInt32LE(offset); offset += 4;
      const sectionSizeHigh = buf.readUInt32LE(offset); offset += 4;
      const sectionSize = sectionSizeLow + sectionSizeHigh * 0x100000000;

      if (sectionType === 1) {
        // Header section
        const fieldSize = buf.readUInt32LE(offset);
        // Skip: fieldSize(4) + prime(fieldSize) + nWires(4) + nPubOutputs(4) + nPubInputs(4) + nPrivInputs(4) + nLabels(8)
        const nConstraintsOffset = offset + 4 + fieldSize + 4 + 4 + 4 + 4 + 8;
        const nConstraints = buf.readUInt32LE(nConstraintsOffset);
        return nConstraints;
      }
      offset += sectionSize;
    }
  } catch (e) {
    console.error(`Could not parse R1CS file: ${e.message}`);
  }
  return 0;
}

// ============================================================
// MAIN
// ============================================================
(async () => {
  console.log(`\n${"═".repeat(70)}`);
  console.log(`  ZK-SNARK Comprehensive Benchmark [FACE vs IRIS]`);
  console.log(`  Architecture: Groth16 + Poseidon Merkle Tree + Nullifier`);
  console.log(`${"═".repeat(70)}`);
  console.log(`  Iterations : ${ITERS} (+ ${WARMUP} warm-up)`);
  console.log(`  Platform   : ${os.type()} ${os.arch()}`);
  console.log(`  CPU        : ${os.cpus()[0]?.model || "unknown"}`);
  console.log(`  Node       : ${process.version}`);
  console.log(`${"═".repeat(70)}\n`);

  // ── Initialize Poseidon ─────────────────────────────────────────────────
  console.log("⏳ Initializing Poseidon...");
  await snark.initPoseidon();
  await snark.getZeroHashes();
  await irisSnark.getIrisZeroHashes();
  console.log("✅ Poseidon ready\n");

  // ── Circuit artifact paths ──────────────────────────────────────────────
  const CIRCUITS = path.join(__dirname, "..", "circuits");
  const FACE_WASM = path.join(CIRCUITS, "face_auth_js", "face_auth.wasm");
  const FACE_ZKEY = path.join(CIRCUITS, "face_auth.zkey");
  const FACE_VKEY = path.join(CIRCUITS, "verification_key.json");
  const FACE_R1CS = path.join(CIRCUITS, "face_auth.r1cs");
  const IRIS_WASM = path.join(CIRCUITS, "iris_auth_js", "iris_auth.wasm");
  const IRIS_ZKEY = path.join(CIRCUITS, "iris_auth.zkey");
  const IRIS_VKEY = path.join(CIRCUITS, "iris_verification_key.json");
  const IRIS_R1CS = path.join(CIRCUITS, "iris_auth.r1cs");

  // ── Register Face test voter ────────────────────────────────────────────
  console.log("⏳ Setting up Face test voter...");
  const FACE_SALT = "a1b2c3d4e5f6789012345678abcdef01";
  const faceEmbReg = generateFakeEmbedding(42);
  const faceRegData = await suppressAsync(() =>
    snark.computeRegistrationData(faceEmbReg, FACE_SALT)
  );

  // Build face commitment pool (10 voters)
  const NUM_VOTERS = 10;
  const faceCommitments = [];
  for (let i = 0; i < NUM_VOTERS - 1; i++) {
    const emb = generateFakeEmbedding(100 + i);
    const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
    const fh = await suppressAsync(() => snark.poseidonHashEmbedding(snark.scaleEmbedding(emb), s));
    const sk = snark.generateSecretKey();
    const c  = await suppressAsync(() => snark.computeCommitment(fh, sk));
    faceCommitments.push(c);
  }
  faceCommitments.push(faceRegData.commitment);
  console.log("✅ Face data ready");

  // ── Register Iris test voter ────────────────────────────────────────────
  console.log("⏳ Setting up Iris test voter...");
  const IRIS_SALT = "b1c2d3e4f5a6789012345678abcdef02";
  const irisCodeReg = generateFakeIrisCode256(42);
  const irisSaltBig = BigInt("0x" + IRIS_SALT);
  const irisHash = await suppressAsync(() => irisSnark.poseidonHashIrisCode(irisCodeReg, irisSaltBig));
  const irisSecretKey = snark.generateSecretKey();
  const irisCommitment = await suppressAsync(() => irisSnark.computeIrisCommitment(irisHash, irisSecretKey));

  const irisCommitments = [];
  for (let i = 0; i < NUM_VOTERS - 1; i++) {
    const code = generateFakeIrisCode256(200 + i);
    const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
    const ih = await suppressAsync(() => irisSnark.poseidonHashIrisCode(code, s));
    const sk = snark.generateSecretKey();
    const c  = await suppressAsync(() => irisSnark.computeIrisCommitment(ih, sk));
    irisCommitments.push(c);
  }
  irisCommitments.push(irisCommitment);
  console.log("✅ Iris data ready\n");

  const electionId = BigInt("12345");

  // =========================================================================
  // SECTION 1: Prove & Verify Latency (Fig 1, 3)
  // =========================================================================
  console.log("━".repeat(70));
  console.log("  SECTION 1: ZK-SNARK Prove & Verify Latency");
  console.log("━".repeat(70));

  const face_witness_times = [], face_prove_times = [], face_verify_times = [];
  const iris_witness_times = [], iris_prove_times = [], iris_verify_times = [];
  const face_nullifier_times = [], iris_nullifier_times = [];
  const face_merkle_times = [], iris_merkle_times = [];

  // Pre-build Merkle proofs (one-time) for leaf index lookup
  async function prepareFaceProofInputs() {
    snark.invalidateMerkleCache();
    const liveEmb = addFaceNoise(faceEmbReg, 0.05);
    const liveScaled = snark.scaleEmbedding(liveEmb);
    const regScaled  = snark.scaleEmbedding(faceEmbReg);
    const commitment = await suppressAsync(() =>
      snark.computeCommitment(faceRegData.faceHash, faceRegData.secretKey)
    );

    let t0 = nowMs();
    const { root, layers, zeroHashes } = await suppressAsync(() =>
      snark.buildMerkleTreeOptimized(faceCommitments)
    );
    const merkleTime = nowMs() - t0;

    const leafIndex = faceCommitments.findIndex(c => c === commitment);
    const { pathElements, pathIndices } = snark.getMerkleProofOptimized(layers, zeroHashes, leafIndex);

    t0 = nowMs();
    const nullifier = await suppressAsync(() =>
      snark.computeNullifier(faceRegData.secretKey, electionId)
    );
    const nullifierTime = nowMs() - t0;

    return { liveScaled, regScaled, root, pathElements, pathIndices, nullifier, merkleTime, nullifierTime };
  }

  async function prepareFaceAndProve(inputs) {
    const { liveScaled, regScaled, root, pathElements, pathIndices, nullifier } = inputs;

    const t0 = nowMs();
    const { proof, publicSignals } = await suppressAsync(() =>
      snark.generateProof(
        liveScaled, regScaled, BigInt("0x" + FACE_SALT),
        faceRegData.secretKey, faceRegData.faceHash,
        root, pathElements, pathIndices, electionId, nullifier, 25n, 100n
      )
    );
    const proveTime = nowMs() - t0;

    const t1 = nowMs();
    const isValid = await suppressAsync(() => snark.verifyProof(proof, publicSignals));
    const verifyTime = nowMs() - t1;

    return { proveTime, verifyTime, isValid, proof, publicSignals };
  }

  async function prepareIrisProofInputs() {
    irisSnark.invalidateIrisMerkleCache();
    const liveCode = addIrisNoise(irisCodeReg, 0.10);

    const commitment = await suppressAsync(() =>
      irisSnark.computeIrisCommitment(irisHash, irisSecretKey)
    );

    let t0 = nowMs();
    const { root, layers, zeroHashes } = await suppressAsync(() =>
      irisSnark.buildIrisMerkleTree(irisCommitments)
    );
    const merkleTime = nowMs() - t0;

    const leafIndex = irisCommitments.findIndex(c => c === commitment);
    const { pathElements, pathIndices } = irisSnark.getIrisMerkleProof(layers, zeroHashes, leafIndex);

    t0 = nowMs();
    const nullifier = await suppressAsync(() =>
      irisSnark.computeIrisNullifier(irisSecretKey, electionId)
    );
    const nullifierTime = nowMs() - t0;

    return { liveCode, root, pathElements, pathIndices, nullifier, merkleTime, nullifierTime };
  }

  async function prepareIrisAndProve(inputs) {
    const { liveCode, root, pathElements, pathIndices, nullifier } = inputs;

    const t0 = nowMs();
    const { proof, publicSignals } = await suppressAsync(() =>
      irisSnark.generateIrisProof(
        liveCode, irisCodeReg, irisSaltBig,
        irisSecretKey, irisHash,
        root, pathElements, pathIndices, electionId, nullifier,
        irisSnark.HAMMING_THRESHOLD
      )
    );
    const proveTime = nowMs() - t0;

    const t1 = nowMs();
    const isValid = await suppressAsync(() => irisSnark.verifyIrisProof(proof, publicSignals));
    const verifyTime = nowMs() - t1;

    return { proveTime, verifyTime, isValid, proof, publicSignals };
  }

  // Warm-up
  console.log(`\n  🔥 Warm-up (${WARMUP} runs)...`);
  for (let i = 0; i < WARMUP; i++) {
    const fi = await prepareFaceProofInputs();
    await prepareFaceAndProve(fi);
    const ii = await prepareIrisProofInputs();
    await prepareIrisAndProve(ii);
  }

  // Main loop
  console.log(`  📊 Running ${ITERS} measured iterations...`);
  for (let i = 0; i < ITERS; i++) {
    // Interleave
    if (i % 2 === 0) {
      const fi = await prepareFaceProofInputs();
      face_merkle_times.push(fi.merkleTime);
      face_nullifier_times.push(fi.nullifierTime);
      const fr = await prepareFaceAndProve(fi);
      face_prove_times.push(fr.proveTime);
      face_verify_times.push(fr.verifyTime);

      const ii = await prepareIrisProofInputs();
      iris_merkle_times.push(ii.merkleTime);
      iris_nullifier_times.push(ii.nullifierTime);
      const ir = await prepareIrisAndProve(ii);
      iris_prove_times.push(ir.proveTime);
      iris_verify_times.push(ir.verifyTime);
    } else {
      const ii = await prepareIrisProofInputs();
      iris_merkle_times.push(ii.merkleTime);
      iris_nullifier_times.push(ii.nullifierTime);
      const ir = await prepareIrisAndProve(ii);
      iris_prove_times.push(ir.proveTime);
      iris_verify_times.push(ir.verifyTime);

      const fi = await prepareFaceProofInputs();
      face_merkle_times.push(fi.merkleTime);
      face_nullifier_times.push(fi.nullifierTime);
      const fr = await prepareFaceAndProve(fi);
      face_prove_times.push(fr.proveTime);
      face_verify_times.push(fr.verifyTime);
    }

    if ((i + 1) % 10 === 0 || i === ITERS - 1) {
      process.stdout.write(`\r  Iteration ${i + 1}/${ITERS}`);
    }
  }
  console.log("\n");

  // =========================================================================
  // SECTION 2: Circuit Artifact Sizes & Constraints (Fig 2, 4)
  // =========================================================================
  console.log("━".repeat(70));
  console.log("  SECTION 2: Circuit Artifacts & Constraints");
  console.log("━".repeat(70));

  const faceConstraints = getR1CSConstraintCount(FACE_R1CS);
  const irisConstraints = getR1CSConstraintCount(IRIS_R1CS);

  console.log(`  Face R1CS constraints: ${faceConstraints.toLocaleString()}`);
  console.log(`  Iris R1CS constraints: ${irisConstraints.toLocaleString()}`);

  const artifactSizes = {
    face: {
      wasm_kb:  fileSizeKB(FACE_WASM),
      zkey_mb:  fileSizeMB(FACE_ZKEY),
      vkey_kb:  fileSizeKB(FACE_VKEY),
      r1cs_kb:  fileSizeKB(FACE_R1CS),
      constraints: faceConstraints,
    },
    iris: {
      wasm_kb:  fileSizeKB(IRIS_WASM),
      zkey_mb:  fileSizeMB(IRIS_ZKEY),
      vkey_kb:  fileSizeKB(IRIS_VKEY),
      r1cs_kb:  fileSizeKB(IRIS_R1CS),
      constraints: irisConstraints,
    },
  };

  console.log(`\n  Face artifacts: WASM=${artifactSizes.face.wasm_kb}KB  zkey=${artifactSizes.face.zkey_mb}MB  vkey=${artifactSizes.face.vkey_kb}KB`);
  console.log(`  Iris artifacts: WASM=${artifactSizes.iris.wasm_kb}KB  zkey=${artifactSizes.iris.zkey_mb}MB  vkey=${artifactSizes.iris.vkey_kb}KB`);

  // Groth16 proof size is constant: 3 group elements = ~192 bytes (compressed: ~128 bytes)
  // Serialize a sample proof to measure exact size
  const sampleFI = await prepareFaceProofInputs();
  const sampleFR = await prepareFaceAndProve(sampleFI);
  const sampleII = await prepareIrisProofInputs();
  const sampleIR = await prepareIrisAndProve(sampleII);

  const faceProofJSON = JSON.stringify(sampleFR.proof);
  const irisProofJSON = JSON.stringify(sampleIR.proof);
  const facePublicJSON = JSON.stringify(sampleFR.publicSignals);
  const irisPublicJSON = JSON.stringify(sampleIR.publicSignals);

  artifactSizes.face.proof_bytes = Buffer.byteLength(faceProofJSON);
  artifactSizes.face.public_signals_bytes = Buffer.byteLength(facePublicJSON);
  artifactSizes.face.public_signals_count = sampleFR.publicSignals.length;
  artifactSizes.iris.proof_bytes = Buffer.byteLength(irisProofJSON);
  artifactSizes.iris.public_signals_bytes = Buffer.byteLength(irisPublicJSON);
  artifactSizes.iris.public_signals_count = sampleIR.publicSignals.length;

  console.log(`  Face proof: ${artifactSizes.face.proof_bytes} bytes (JSON), ${artifactSizes.face.public_signals_count} public signals`);
  console.log(`  Iris proof: ${artifactSizes.iris.proof_bytes} bytes (JSON), ${artifactSizes.iris.public_signals_count} public signals`);

  // =========================================================================
  // SECTION 3: Nullifier Double-Vote Detection (Fig 5)
  // =========================================================================
  console.log("\n" + "━".repeat(70));
  console.log("  SECTION 3: Nullifier Double-Vote Detection");
  console.log("━".repeat(70));

  const NULLIFIER_TRIALS = 500;
  let truePositives = 0;  // Same voter, same election → same nullifier
  let trueNegatives = 0;  // Different voter/election → different nullifier
  const nullifier_compute_times = [];

  for (let i = 0; i < NULLIFIER_TRIALS; i++) {
    // True positive: same key + same electionId → identical nullifier
    const t0 = nowMs();
    const n1 = await suppressAsync(() => snark.computeNullifier(faceRegData.secretKey, electionId));
    nullifier_compute_times.push(nowMs() - t0);
    const n2 = await suppressAsync(() => snark.computeNullifier(faceRegData.secretKey, electionId));
    if (n1 === n2) truePositives++;

    // True negative: different key → different nullifier
    const differentKey = snark.generateSecretKey();
    const n3 = await suppressAsync(() => snark.computeNullifier(differentKey, electionId));
    if (n1 !== n3) trueNegatives++;
  }

  // Also test across elections
  let crossElectionTN = 0;
  for (let i = 0; i < NULLIFIER_TRIALS; i++) {
    const n1 = await suppressAsync(() => snark.computeNullifier(faceRegData.secretKey, electionId));
    const n2 = await suppressAsync(() => snark.computeNullifier(faceRegData.secretKey, BigInt(99999 + i)));
    if (n1 !== n2) crossElectionTN++;
  }

  const nullifierResults = {
    trials: NULLIFIER_TRIALS,
    true_positives: truePositives,
    true_negatives: trueNegatives,
    cross_election_true_negatives: crossElectionTN,
    detection_accuracy_pct: +((truePositives / NULLIFIER_TRIALS) * 100).toFixed(2),
    false_positive_rate_pct: +(((NULLIFIER_TRIALS - trueNegatives) / NULLIFIER_TRIALS) * 100).toFixed(4),
    compute_time: calcStats(nullifier_compute_times),
  };

  console.log(`  True Positives (same voter detected):    ${truePositives}/${NULLIFIER_TRIALS}`);
  console.log(`  True Negatives (different voter cleared): ${trueNegatives}/${NULLIFIER_TRIALS}`);
  console.log(`  Cross-Election TN:                        ${crossElectionTN}/${NULLIFIER_TRIALS}`);
  console.log(`  Detection accuracy:                       ${nullifierResults.detection_accuracy_pct}%`);
  console.log(`  Nullifier compute:                        ${nullifierResults.compute_time.trimmedMean}ms`);

  // =========================================================================
  // SECTION 4: Merkle Tree Scalability (Fig 6)
  // =========================================================================
  console.log("\n" + "━".repeat(70));
  console.log("  SECTION 4: Merkle Tree Scalability vs Voter Count");
  console.log("━".repeat(70));

  const MERKLE_VOTER_SWEEP = [2, 5, 10, 25, 50, 100, 200];
  const MERKLE_ITERS = Math.min(ITERS, 20);
  const merkleSweep = [];

  for (const N of MERKLE_VOTER_SWEEP) {
    // Build face commitments pool of size N
    const comms = [];
    for (let i = 0; i < N; i++) {
      const emb = generateFakeEmbedding(300 + i);
      const s = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
      const fh = await suppressAsync(() => snark.poseidonHashEmbedding(snark.scaleEmbedding(emb), s));
      const sk = snark.generateSecretKey();
      const c  = await suppressAsync(() => snark.computeCommitment(fh, sk));
      comms.push(c);
    }

    const build_times = [];
    const proof_times = [];

    for (let iter = 0; iter < MERKLE_ITERS; iter++) {
      snark.invalidateMerkleCache();

      const t0 = nowMs();
      const { root, layers, zeroHashes } = await suppressAsync(() =>
        snark.buildMerkleTreeOptimized(comms)
      );
      build_times.push(nowMs() - t0);

      const t1 = nowMs();
      snark.getMerkleProofOptimized(layers, zeroHashes, 0);
      proof_times.push(nowMs() - t1);
    }

    merkleSweep.push({
      voters: N,
      build: calcStats(build_times),
      proof_gen: calcStats(proof_times),
    });

    console.log(`  N=${String(N).padEnd(4)} build=${calcStats(build_times).trimmedMean}ms  proof=${calcStats(proof_times).trimmedMean}ms`);
  }

  // =========================================================================
  // SECTION 5: Throughput (Fig 3)
  // =========================================================================
  console.log("\n" + "━".repeat(70));
  console.log("  SECTION 5: Throughput (proofs/sec)");
  console.log("━".repeat(70));

  const faceProveStats = calcStats(face_prove_times);
  const irisProveStats = calcStats(iris_prove_times);
  const faceVerifyStats = calcStats(face_verify_times);
  const irisVerifyStats = calcStats(iris_verify_times);

  const faceThroughput = {
    prove_per_sec:  +(1000 / faceProveStats.trimmedMean).toFixed(2),
    verify_per_sec: +(1000 / faceVerifyStats.trimmedMean).toFixed(2),
  };
  const irisThroughput = {
    prove_per_sec:  +(1000 / irisProveStats.trimmedMean).toFixed(2),
    verify_per_sec: +(1000 / irisVerifyStats.trimmedMean).toFixed(2),
  };

  console.log(`  Face throughput: ${faceThroughput.prove_per_sec} proofs/sec, ${faceThroughput.verify_per_sec} verif/sec`);
  console.log(`  Iris throughput: ${irisThroughput.prove_per_sec} proofs/sec, ${irisThroughput.verify_per_sec} verif/sec`);

  // =========================================================================
  // Print summary
  // =========================================================================
  console.log("\n" + "═".repeat(70));
  console.log("  SUMMARY");
  console.log("═".repeat(70));
  console.log(`  ${"Metric".padEnd(35)} ${"Face".padStart(12)} ${"Iris".padStart(12)} ${"Ratio".padStart(10)}`);
  console.log(`  ${"─".repeat(70)}`);
  console.log(`  ${"R1CS Constraints".padEnd(35)} ${String(faceConstraints).padStart(12)} ${String(irisConstraints).padStart(12)} ${(faceConstraints / (irisConstraints || 1)).toFixed(1).padStart(10)}×`);
  console.log(`  ${"Prove Time (ms)".padEnd(35)} ${faceProveStats.trimmedMean.toFixed(1).padStart(12)} ${irisProveStats.trimmedMean.toFixed(1).padStart(12)} ${(faceProveStats.trimmedMean / irisProveStats.trimmedMean).toFixed(1).padStart(10)}×`);
  console.log(`  ${"Verify Time (ms)".padEnd(35)} ${faceVerifyStats.trimmedMean.toFixed(1).padStart(12)} ${irisVerifyStats.trimmedMean.toFixed(1).padStart(12)} ${(faceVerifyStats.trimmedMean / irisVerifyStats.trimmedMean).toFixed(1).padStart(10)}×`);
  console.log(`  ${"Proving Key (MB)".padEnd(35)} ${artifactSizes.face.zkey_mb.toFixed(2).padStart(12)} ${artifactSizes.iris.zkey_mb.toFixed(2).padStart(12)} ${(artifactSizes.face.zkey_mb / (artifactSizes.iris.zkey_mb || 1)).toFixed(1).padStart(10)}×`);
  console.log(`  ${"WASM Size (KB)".padEnd(35)} ${artifactSizes.face.wasm_kb.toFixed(1).padStart(12)} ${artifactSizes.iris.wasm_kb.toFixed(1).padStart(12)} ${(artifactSizes.face.wasm_kb / (artifactSizes.iris.wasm_kb || 1)).toFixed(1).padStart(10)}×`);

  // =========================================================================
  // Save results
  // =========================================================================
  const results = {
    meta: {
      date: new Date().toISOString(),
      platform: `${os.type()} ${os.arch()}`,
      cpu: os.cpus()[0]?.model || "unknown",
      node: process.version,
      iterations: ITERS,
      warmup: WARMUP,
      voters: NUM_VOTERS,
      merkle_depth: 20,
      architecture: "ZK-SNARK (Groth16) + Poseidon Merkle Tree + Nullifier",
    },
    // Fig 1 & 3 data
    latency: {
      face: {
        prove:     calcStats(face_prove_times),
        verify:    calcStats(face_verify_times),
        merkle:    calcStats(face_merkle_times),
        nullifier: calcStats(face_nullifier_times),
      },
      iris: {
        prove:     calcStats(iris_prove_times),
        verify:    calcStats(iris_verify_times),
        merkle:    calcStats(iris_merkle_times),
        nullifier: calcStats(iris_nullifier_times),
      },
    },
    throughput: {
      face: faceThroughput,
      iris: irisThroughput,
    },
    // Fig 2 & 4 data
    artifacts: artifactSizes,
    // Fig 5 data
    nullifier: nullifierResults,
    // Fig 6 data
    merkle_scalability: merkleSweep,
  };

  const outPath = path.join(__dirname, "zksnark_results.json");
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log(`\n  ✓ Saved ${outPath}`);
  console.log(`  → Next: python benchmark/zksnark_plot.py\n`);
})();
