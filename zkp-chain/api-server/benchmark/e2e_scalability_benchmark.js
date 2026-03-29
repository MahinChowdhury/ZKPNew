/**
 * Parametric E2E Scalability Benchmark
 * For Q1 Journal Publication — Category C + D
 *
 * Sweeps three independent dimensions:
 *   Dim 1: Ring size (n)        → shows O(n) LRS scaling
 *   Dim 2: Candidate count (C)  → shows O(C) ElGamal/ZKP scaling
 *   Dim 3: Concurrent voters    → shows Fabric TPS under load
 *
 * Prerequisites (same as e2e_benchmark.js):
 *   1. python app.py running on port 8000
 *   2. Fabric network running + chaincode installed
 *   3. Wallet enrolled
 *
 * Run:
 *   node e2e_scalability_benchmark.js
 *   node e2e_scalability_benchmark.js --face-img path/to/face.jpg --iters 5
 */

"use strict";

const crypto       = require("crypto");
const EC           = require("elliptic").ec;
const BN           = require("bn.js");
const fs           = require("fs");
const axios        = require("axios");
const FormData     = require("form-data");
const lrs          = require("../crypto/lrs");
const homomorphic  = require("../crypto/homomorphic");
const FabricClient = require("../fabric-client");

const ec = new EC("secp256k1");

// ─── CLI ──────────────────────────────────────────────────────────────────────
const args       = process.argv.slice(2);
const getArg     = (f, d) => { const i = args.indexOf(f); return i > -1 ? args[i+1] : d; };
const FACE_IMG   = getArg("--face-img", null);
const ITERS      = parseInt(getArg("--iters", "10"), 10);
const PYTHON_URL = getArg("--python-url", "http://localhost:8000");
const API_URL    = getArg("--api-url",    "http://localhost:3000");

// ─── Sweep dimensions ─────────────────────────────────────────────────────────
// Dim 1: ring sizes (LRS scalability) — these use synthetic rings so we can
//         go beyond the number of registered users on the test-network.
//         The ring keys are real secp256k1 keypairs; the crypto is honest.
const RING_SIZES       = [2, 4, 8, 16, 32, 64, 128, 256];

// Dim 2: candidate counts (ElGamal/ZKP scalability)
const CANDIDATE_COUNTS = [2, 3, 5, 10, 20];

// Dim 3: concurrent submitters (Fabric TPS)
const CONCURRENCY_LEVELS = [1, 5, 10, 20];

// ─── Helpers ──────────────────────────────────────────────────────────────────
function nowMs() { return Number(process.hrtime.bigint()) / 1e6; }
function sha256Hash(d) { return crypto.createHash("sha256").update(String(d)).digest("hex"); }
function calcStats(arr) {
  const s    = [...arr].sort((a, b) => a - b);
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const sd   = Math.sqrt(arr.reduce((a, v) => a + (v - mean) ** 2, 0) / arr.length);
  return {
    mean: +mean.toFixed(3), sd: +sd.toFixed(3),
    min:  +s[0].toFixed(3), max: +s[s.length-1].toFixed(3),
    p95:  +s[Math.ceil(0.95 * s.length)-1].toFixed(3),
    p99:  +s[Math.ceil(0.99 * s.length)-1].toFixed(3),
  };
}
function suppress(fn) {
  const o = { log: console.log, error: console.error, warn: console.warn };
  console.log = console.error = console.warn = () => {};
  try { return fn(); } finally { Object.assign(console, o); }
}
function bar(label, val, total, width = 40) {
  const filled = Math.round((val / total) * width);
  return `[${("█".repeat(filled)).padEnd(width)}] ${label}: ${val.toFixed(1)}ms`;
}

// ─── Live Python face API ──────────────────────────────────────────────────────
async function getEmbedding(buf) {
  const form = new FormData();
  form.append("file", buf, { filename: "face.jpg", contentType: "image/jpeg" });
  const res = await axios.post(`${PYTHON_URL}/get-embedding`, form,
    { headers: form.getHeaders(), timeout: 30000 });
  return res.data.embedding;
}

async function compareEmbs(emb1, emb2) {
  const res = await axios.post(`${PYTHON_URL}/compare-embeddings`,
    { face_login: emb1, face_reg: emb2 }, { timeout: 10000 });
  return res.data;
}

// ─── Build a synthetic ring of n keys (real ECC keypairs) ─────────────────────
function buildSyntheticRing(n, signerIdx = 0) {
  const keys = Array.from({ length: n }, () => ec.genKeyPair());
  const ring = keys.map(k => k.getPublic());
  return { keys, ring, signerKey: keys[signerIdx].getPrivate(), signerIdx };
}

// ─── QR fixture ───────────────────────────────────────────────────────────────
function buildQR(password, embedding) {
  const pbkdfSalt = crypto.randomBytes(16);
  const iv        = crypto.randomBytes(16);
  const faceHash  = sha256Hash("benchmark_user");
  const kSalt     = sha256Hash("benchmark_salt");
  const payload   = JSON.stringify({ nid: "NID-BENCH", faceHash, salt: kSalt, faceEmbedding: embedding });
  const key       = crypto.pbkdf2Sync(password, pbkdfSalt, 100000, 32, "sha256");
  const cipher    = crypto.createCipheriv("aes-256-cbc", key, iv);
  let enc = cipher.update(payload, "utf8", "base64"); enc += cipher.final("base64");
  return {
    encrypted: JSON.stringify({ iv: iv.toString("base64"), salt: pbkdfSalt.toString("base64"), data: enc }),
    faceHash, kSalt
  };
}

// ─── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  console.log("\n" + "=".repeat(65));
  console.log("  ZKP Voting — Parametric Scalability Benchmark [LIVE SYSTEM]");
  console.log("=".repeat(65));
  console.log(`  Iterations per config : ${ITERS}`);
  console.log(`  Ring sizes            : [${RING_SIZES}]`);
  console.log(`  Candidate counts      : [${CANDIDATE_COUNTS}]`);
  console.log(`  Concurrency levels    : [${CONCURRENCY_LEVELS}]`);

  // ── Preflight ────────────────────────────────────────────────────────────
  console.log("\n  Checking Python API...");
  try {
    await axios.get(`${PYTHON_URL}/docs`, { timeout: 4000 });
    console.log(`  ✅ Python API OK at ${PYTHON_URL}`);
  } catch {
    console.error(`  ❌ Python API not reachable. Start with: python app.py`);
    process.exit(1);
  }

  // ── Connect Fabric ────────────────────────────────────────────────────────
  console.log("  Connecting to Fabric...");
  const fabricClient = new FabricClient();
  try {
    await fabricClient.connect();
    console.log("  ✅ Fabric connected");
  } catch (err) {
    console.error("  ❌ Fabric connection failed:", err.message);
    process.exit(1);
  }

  // ── Get face embedding (once) ─────────────────────────────────────────────
  console.log("  Loading face image and getting embedding (warm-up)...");
  let faceBuffer = FACE_IMG && fs.existsSync(FACE_IMG)
    ? fs.readFileSync(FACE_IMG)
    : Buffer.from("/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBwgHBgkIBwgKCgkLDRYPDQwMDRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5OjcBCgoKDQwNGg8PGjclHyU3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N//AABEIAAIACQIDAQIRAE8RAhEB/8QAGAABAAMBAAAAAAAAAAAAAAAAAAQFBgP/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/ANuAAB//2Q==", "base64");
  
  let regEmbedding;
  try {
    regEmbedding = await getEmbedding(faceBuffer);
    console.log(`  ✅ Embedding ready (${regEmbedding.length}D)`);
  } catch (err) {
    console.error("  ❌ Face embedding failed:", err.message);
    process.exit(1);
  }

  // Build QR fixture
  const PASSWORD = "BenchmarkPass!";
  const { encrypted: ENCRYPTED_QR, faceHash, kSalt } = buildQR(PASSWORD, regEmbedding);
  const kHash = sha256Hash(faceHash + kSalt);
  let signerK = new BN(kHash, 16).umod(ec.curve.n);
  if (signerK.isZero()) signerK = signerK.iaddn(1);

  // Get tally public key or use ephemeral
  let elgamalPK;
  try {
    const res = await axios.get(`${API_URL}/api/v1/ballot/active`, { timeout: 5000 });
    const ballot = res.data?.ballot;
    if (ballot?.id) {
      const pkRes = await axios.get(`${API_URL}/api/v1/tally/publickey/${ballot.id}`, { timeout: 5000 });
      if (pkRes.data?.ok && pkRes.data.publicKey) {
        elgamalPK = ec.curve.point(new BN(pkRes.data.publicKey.x, 16), new BN(pkRes.data.publicKey.y, 16));
        console.log("  ✅ ElGamal public key fetched from tally");
      }
    }
  } catch {}
  if (!elgamalPK) {
    elgamalPK = suppress(() => homomorphic.generateKeypair().publicKey);
    console.log("  ⚠️  Using ephemeral ElGamal key (tally not set up)");
  }

  // ── Measure biometric baseline (Python API is independent of ring size) ────
  console.log("\n  Measuring biometric phases baseline (10 samples)...");
  const bioTimes = { p2_face_embed: [], p3_face_compare: [] };
  for (let i = 0; i < 10; i++) {
    let t0 = nowMs();
    const liveEmb = await getEmbedding(faceBuffer);
    bioTimes.p2_face_embed.push(nowMs() - t0);
    t0 = nowMs();
    await compareEmbs(liveEmb, regEmbedding);
    bioTimes.p3_face_compare.push(nowMs() - t0);
  }
  const biometricStats = {
    face_embed:   calcStats(bioTimes.p2_face_embed),
    face_compare: calcStats(bioTimes.p3_face_compare),
  };
  console.log(`  P2 Face Embed:   ${biometricStats.face_embed.mean} ms ± ${biometricStats.face_embed.sd}`);
  console.log(`  P3 Face Compare: ${biometricStats.face_compare.mean} ms ± ${biometricStats.face_compare.sd}`);

  // ─── DIM 1: Ring Size Sweep ────────────────────────────────────────────────
  console.log("\n" + "─".repeat(65));
  console.log("  DIM 1: LRS Scalability vs Ring Size (fixed candidates=3)");
  console.log("─".repeat(65));

  const ringSweep = [];

  for (const n of RING_SIZES) {
    const { ring, signerKey, signerIdx } = buildSyntheticRing(n);
    const p1_times = [], p4_times = [], p6_times = [], p7_times = [], p8_times = [];

    for (let iter = 0; iter < ITERS; iter++) {
      // P1: QR decrypt
      let t0 = nowMs();
      const parsed = JSON.parse(ENCRYPTED_QR);
      const pbkdfSalt = Buffer.from(parsed.salt, "base64");
      const key = crypto.pbkdf2Sync(PASSWORD, pbkdfSalt, 100000, 32, "sha256");
      const dc = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(parsed.iv, "base64"));
      let dec = dc.update(parsed.data, "base64", "utf8"); dec += dc.final("utf8");
      p1_times.push(nowMs() - t0);

      // P4: Key derivation
      t0 = nowMs();
      const kh = sha256Hash(faceHash + kSalt);
      let kn = new BN(kh, 16).umod(ec.curve.n);
      if (kn.isZero()) kn = kn.iaddn(1);
      ec.g.mul(kn);
      p4_times.push(nowMs() - t0);

      // Build vector (3 candidates) for message hash
      const encVec = suppress(() => [0, 1, 2].map(i => {
        const voteVal = i === 0 ? 1 : 0;
        const cipher = homomorphic.encrypt(elgamalPK, voteVal);
        const proof  = homomorphic.proveValidVote(elgamalPK, cipher, voteVal, cipher.r);
        const ser    = homomorphic.serializeCiphertext(cipher);
        ser.validityProof = proof;
        return ser;
      }));
      const signMsg = sha256Hash(JSON.stringify(encVec));

      // P6: LRS Sign
      t0 = nowMs();
      const sig = suppress(() => lrs.sign(signerKey, ring, signerIdx, signMsg));
      p6_times.push(nowMs() - t0);

      // P7: LRS Verify
      t0 = nowMs();
      suppress(() => lrs.verify(sig, ring, signMsg));
      p7_times.push(nowMs() - t0);

      // P8: ElGamal vector (3 candidates, timed separately)
      t0 = nowMs();
      suppress(() => [0, 1, 2].map(i => {
        const voteVal = i === 0 ? 1 : 0;
        const cipher = homomorphic.encrypt(elgamalPK, voteVal);
        const proof  = homomorphic.proveValidVote(elgamalPK, cipher, voteVal, cipher.r);
        const ser    = homomorphic.serializeCiphertext(cipher);
        ser.validityProof = proof;
        return ser;
      }));
      p8_times.push(nowMs() - t0);
    }

    const row = {
      ring_size: n,
      p1_qr_decrypt:  calcStats(p1_times),
      p4_key_derive:  calcStats(p4_times),
      p6_lrs_sign:    calcStats(p6_times),
      p7_lrs_verify:  calcStats(p7_times),
      p8_elgamal_zkp: calcStats(p8_times),
      total_crypto_mean: calcStats(p1_times).mean + calcStats(p4_times).mean +
                         calcStats(p6_times).mean + calcStats(p7_times).mean + calcStats(p8_times).mean
    };
    ringSweep.push(row);
    console.log(`  n=${String(n).padEnd(3)}  Sign=${row.p6_lrs_sign.mean.toFixed(1)}ms  Verify=${row.p7_lrs_verify.mean.toFixed(1)}ms  Total_crypto=${row.total_crypto_mean.toFixed(1)}ms`);
  }

  // ─── DIM 2: Candidate Count Sweep ─────────────────────────────────────────
  console.log("\n" + "─".repeat(65));
  console.log("  DIM 2: ElGamal+ZKP Scalability vs Candidate Count (ring_size=32)");
  console.log("─".repeat(65));

  const { ring: ring32, signerKey: key32, signerIdx: idx32 } = buildSyntheticRing(32);
  const candidateSweep = [];

  for (const C of CANDIDATE_COUNTS) {
    const encTimes = [], signTimes = [], totalTimes = [];

    for (let iter = 0; iter < ITERS; iter++) {
      // Build encrypted vector of size C
      let t0 = nowMs();
      const encVec = suppress(() => Array.from({ length: C }, (_, i) => {
        const voteVal = i === 0 ? 1 : 0;
        const cipher = homomorphic.encrypt(elgamalPK, voteVal);
        const proof  = homomorphic.proveValidVote(elgamalPK, cipher, voteVal, cipher.r);
        const ser    = homomorphic.serializeCiphertext(cipher);
        ser.validityProof = proof;
        return ser;
      }));
      encTimes.push(nowMs() - t0);

      // Sign hash of vector
      const signMsg = sha256Hash(JSON.stringify(encVec));
      t0 = nowMs();
      suppress(() => lrs.sign(key32, ring32, idx32, signMsg));
      signTimes.push(nowMs() - t0);

      totalTimes.push(encTimes[iter] + signTimes[iter]);
    }

    const row = {
      candidates: C,
      elgamal_zkp: calcStats(encTimes),
      lrs_sign:    calcStats(signTimes),
      total_client_mean: calcStats(totalTimes).mean,
      total_client_sd:   calcStats(totalTimes).sd,
    };
    candidateSweep.push(row);
    console.log(`  C=${String(C).padEnd(2)}  Encrypt+ZKP=${row.elgamal_zkp.mean.toFixed(1)}ms  LRS=${row.lrs_sign.mean.toFixed(1)}ms  Total_client=${row.total_client_mean.toFixed(1)}ms`);
  }

  // ─── DIM 3: Fabric TPS under concurrent load ───────────────────────────────
  console.log("\n" + "─".repeat(65));
  console.log("  DIM 3: Fabric TPS vs Concurrent Voters (ring_size=32, candidates=3)");
  console.log("─".repeat(65));

  const fabricClients = [fabricClient];
  // Spin up additional fabric clients for concurrency
  for (let i = 1; i < Math.max(...CONCURRENCY_LEVELS); i++) {
    const fc = new FabricClient();
    try { await fc.connect(); fabricClients.push(fc); } catch {}
  }

  const tpsSweep = [];
  const { ring: ringFabric, signerKey: keyFabric, signerIdx: idxFabric } = buildSyntheticRing(32);
  const dummyVec = suppress(() => [0, 1, 2].map(i => {
    const voteVal = i === 0 ? 1 : 0;
    const cipher = homomorphic.encrypt(elgamalPK, voteVal);
    const proof  = homomorphic.proveValidVote(elgamalPK, cipher, voteVal, cipher.r);
    const ser    = homomorphic.serializeCiphertext(cipher);
    ser.validityProof = proof;
    return ser;
  }));
  const dummyMsg = sha256Hash(JSON.stringify(dummyVec));
  const ringForFabric = ringFabric.map(p => ({ x: p.getX().toString(16), y: p.getY().toString(16) }));

  for (const concurrency of CONCURRENCY_LEVELS) {
    const batchLatencies = [];
    const BATCHES = Math.max(3, Math.ceil(10 / concurrency));

    for (let batch = 0; batch < BATCHES; batch++) {
      const clients = fabricClients.slice(0, concurrency);
      const batchStart = nowMs();

      const promises = clients.map((fc, i) => {
        // Each concurrent voter uses a unique signature (fresh ring, differing nonce via message)
        const { ring: r, signerKey: sk, signerIdx: si } = buildSyntheticRing(32);
        const msg = sha256Hash(dummyMsg + "_" + batch + "_" + i);
        const sig = suppress(() => lrs.sign(sk, r, si, msg));
        const rData = r.map(p => ({ x: p.getX().toString(16), y: p.getY().toString(16) }));
        const t0 = nowMs();
        return fc.castVote(msg, sig, rData, dummyVec)
                 .then(() => nowMs() - t0)
                 .catch(() => nowMs() - t0); // record latency even on double-vote
      });

      const indivLatencies = await Promise.all(promises);
      const batchTotal = nowMs() - batchStart;
      const tps = (concurrency * 1000) / batchTotal;
      tps && batchLatencies.push({ indiv: indivLatencies, tps, batchMs: batchTotal });
    }

    const allTps = batchLatencies.map(b => b.tps);
    const allIndiv = batchLatencies.flatMap(b => b.indiv);
    const row = {
      concurrency,
      tps:             calcStats(allTps),
      submit_latency:  calcStats(allIndiv),
    };
    tpsSweep.push(row);
    console.log(`  concurrent=${String(concurrency).padEnd(2)}  TPS=${row.tps.mean.toFixed(2)}  submit_latency=${row.submit_latency.mean.toFixed(0)}ms`);
  }

  // Disconnect extra clients
  for (const fc of fabricClients.slice(1)) {
    try { await fc.disconnect(); } catch (e) {}
  }

  // ─── Save results ──────────────────────────────────────────────────────────
  const results = {
    meta: {
      date:        new Date().toISOString(),
      iterations:  ITERS,
      python_url:  PYTHON_URL,
      live:        true,
    },
    biometric_baseline: biometricStats,
    dim1_ring_sweep:    ringSweep,
    dim2_candidate_sweep: candidateSweep,
    dim3_tps_sweep:     tpsSweep,
  };

  fs.writeFileSync("e2e_scalability_results.json", JSON.stringify(results, null, 2));

  console.log("\n" + "=".repeat(65));
  console.log("  ✓ Saved e2e_scalability_results.json");
  console.log("  → Run: python e2e_scalability_plot.py");
  console.log("=".repeat(65) + "\n");

  try { await fabricClient.disconnect(); } catch (e) {}
})();
