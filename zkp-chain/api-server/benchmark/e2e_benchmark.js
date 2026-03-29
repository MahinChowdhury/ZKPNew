/**
 * E2E Vote Casting Pipeline Benchmark (Category C — Implementation Plan)
 *
 * Measures each phase of the vote flow independently with real crypto operations.
 * Network-dependent phases (Fabric submit, Python face API) are measured separately
 * using a realistic stub so the cryptographic numbers are always reproducible.
 *
 * Pipeline phases timed:
 *   P1 — QR Decode + PBKDF2 + AES-256-CBC Decrypt
 *   P2 — Face Embedding (mocked: Python API round-trip stub)
 *   P3 — Cosine Similarity Comparison (mocked: compare embedding arrays)
 *   P4 — Key Derivation (SHA-256 → BN scalar k, compute S=k·G)
 *   P5 — Ring Fetch + LRS Sign (real LRS.sign)
 *   P6 — LRS Local Verify (real LRS.verify)
 *   P7 — ElGamal Vector Encryption + ZKP per candidate (real crypto)
 *   P8 — Fabric Submit (stub, configurable with live flag)
 *
 * Run: node e2e_benchmark.js [--live]
 *   --live  → uses real Fabric client for P8 (requires network + wallet)
 */

"use strict";

const crypto   = require("crypto");
const EC       = require("elliptic").ec;
const BN       = require("bn.js");
const fs       = require("fs");
const lrs      = require("../crypto/lrs");
const homomorphic = require("../crypto/homomorphic");

const ec = new EC("secp256k1");

// ─── helpers ──────────────────────────────────────────────────────────────────

function nowMs() { return Number(process.hrtime.bigint()) / 1e6; }

function sha256Hash(data) {
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}

function calcStats(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const sd   = Math.sqrt(arr.reduce((a, v) => a + (v - mean) ** 2, 0) / arr.length);
  return {
    mean: +mean.toFixed(3),
    sd:   +sd.toFixed(3),
    min:  +s[0].toFixed(3),
    max:  +s[s.length - 1].toFixed(3),
    p95:  +s[Math.ceil(0.95 * s.length) - 1].toFixed(3),
    p99:  +s[Math.ceil(0.99 * s.length) - 1].toFixed(3),
  };
}

function suppress(fn) {
  const o = { log: console.log, error: console.error, warn: console.warn };
  console.log = () => {}; console.error = () => {}; console.warn = () => {};
  try { return fn(); } finally { Object.assign(console, o); }
}

// ─── benchmark config ─────────────────────────────────────────────────────────

const ITERS          = 30;
const CANDIDATES     = 3;      // simulate a 3-option ballot
const RING_SIZE      = 32;     // typical election ring size
const LIVE_FABRIC    = process.argv.includes("--live");

console.log(`\n${"=".repeat(60)}`);
console.log(`  ZKP Voting System — E2E Latency Benchmark`);
console.log(`${"=".repeat(60)}`);
console.log(`  Iterations  : ${ITERS}`);
console.log(`  Candidates  : ${CANDIDATES}`);
console.log(`  Ring size   : ${RING_SIZE}`);
console.log(`  Fabric stub : ${LIVE_FABRIC ? "LIVE" : "mocked"}`);
console.log(`${"=".repeat(60)}\n`);

// ─── synthetic fixtures ────────────────────────────────────────────────────────

// Simulated face embedding (512-dim normalised float array, like FaceNet output)
function makeFakeEmbedding(seed = 0) {
  const arr = [];
  let x = seed + 1;
  for (let i = 0; i < 512; i++) { x = (x * 1664525 + 1013904223) >>> 0; arr.push((x / 0xFFFFFFFF) * 2 - 1); }
  const norm = Math.sqrt(arr.reduce((s, v) => s + v * v, 0));
  return arr.map(v => v / norm);
}

const REGISTERED_EMBEDDING = makeFakeEmbedding(42);
// Live embedding = same person, slightly different angle/lighting → add small noise
const LIVE_EMBEDDING = REGISTERED_EMBEDDING.map(v => v + (Math.random() * 0.02 - 0.01));
// Re-normalise
const livNorm = Math.sqrt(LIVE_EMBEDDING.reduce((s, v) => s + v * v, 0));
for (let i = 0; i < LIVE_EMBEDDING.length; i++) LIVE_EMBEDDING[i] /= livNorm;

// Simulated QR payload (encrypted with PBKDF2+AES just like the real registration flow)
function makeQrPayload(password) {
  const salt   = crypto.randomBytes(16);
  const iv     = crypto.randomBytes(16);
  const faceHash = sha256Hash("user_face_" + Date.now());
  const kSalt  = sha256Hash("user_salt_" + Date.now());

  const payload = JSON.stringify({
    nid: "NID-BENCHMARK-001",
    faceHash,
    salt: kSalt,
    faceEmbedding: REGISTERED_EMBEDDING
  });

  const key    = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let enc = cipher.update(payload, "utf8", "base64");
  enc += cipher.final("base64");

  return {
    encrypted: JSON.stringify({ iv: iv.toString("base64"), data: enc, salt: salt.toString("base64") }),
    faceHash,
    kSalt
  };
}

// Build a ring of RING_SIZE random keypairs
function buildRing(signerIdx) {
  const keys = [];
  for (let i = 0; i < RING_SIZE; i++) {
    const kp = ec.genKeyPair();
    keys.push({ privateKey: kp.getPrivate(), publicPoint: kp.getPublic() });
  }
  return keys;
}

// ─── phase timing arrays ──────────────────────────────────────────────────────

const times = {
  p1_qr_decrypt:       [],
  p2_face_embed:       [],
  p3_face_compare:     [],
  p4_key_derive:       [],
  p5_lrs_sign:         [],
  p6_lrs_verify:       [],
  p7_elgamal_vector:   [],
  p8_fabric_submit:    [],
};

// ─── generate fixtures once ───────────────────────────────────────────────────

const PASSWORD     = "BenchmarkPass123!";
const { encrypted: ENCRYPTED_QR, faceHash: FACE_HASH, kSalt: K_SALT } = makeQrPayload(PASSWORD);
const RING_KEYS    = buildRing(0);
const RING_POINTS  = RING_KEYS.map(k => k.publicPoint);
const SIGNER_IDX   = 0;
const SIGNER_K     = RING_KEYS[SIGNER_IDX].privateKey;

// ElGamal keypair for encryption
const elgamalKp    = suppress(() => homomorphic.generateKeypair());
const VOTE_CHOICE  = 0; // choosing candidate 0

// ─── Fabric mock ─────────────────────────────────────────────────────────────

async function fabricSubmitMock(signature, ringData, encryptedVector) {
  // Simulate the network + endorsement latency of Hyperledger Fabric
  // Based on Fabric benchmarks: ~200-600ms on a single-node local network
  const simulatedLatency = 200 + Math.random() * 50;
  await new Promise(r => setTimeout(r, simulatedLatency));
  return { voteId: "vote_" + Date.now(), timestamp: new Date().toISOString() };
}

async function fabricSubmitLive(signature, ringData, encryptedVector) {
  // Live path — only runs with --live flag
  const fabricClient = require("../fabric-client");
  await fabricClient.connect();
  return fabricClient.castVote(signature, ringData, encryptedVector);
}

const fabricSubmit = LIVE_FABRIC ? fabricSubmitLive : fabricSubmitMock;

// ─── Face API mock ────────────────────────────────────────────────────────────

async function getFaceEmbeddingMock(imageBuffer) {
  // Simulates Python FaceNet + PCA API round-trip (~80-150ms typical)
  const latency = 80 + Math.random() * 40;
  await new Promise(r => setTimeout(r, latency));
  return LIVE_EMBEDDING;
}

function cosineCompare(emb1, emb2, threshold = 0.5) {
  const dot = emb1.reduce((s, v, i) => s + v * emb2[i], 0);
  return dot > threshold;
}

// ─── main benchmark loop ──────────────────────────────────────────────────────

console.log(`Running ${ITERS} iterations...\n`);

let iter = 0;
async function runIter() {
  // ── Phase 1: QR Decode + PBKDF2 + AES Decrypt ──
  let t0 = nowMs();
  const parsed = JSON.parse(ENCRYPTED_QR);
  const pbkdfSalt = Buffer.from(parsed.salt, "base64");
  const key     = crypto.pbkdf2Sync(PASSWORD, pbkdfSalt, 100000, 32, "sha256");
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(parsed.iv, "base64"));
  let dec = decipher.update(parsed.data, "base64", "utf8");
  dec += decipher.final("utf8");
  const qrData = JSON.parse(dec);
  times.p1_qr_decrypt.push(nowMs() - t0);

  // ── Phase 2: Face Embedding (Python API) ──
  t0 = nowMs();
  const liveEmbedding = await getFaceEmbeddingMock(null);
  times.p2_face_embed.push(nowMs() - t0);

  // ── Phase 3: Cosine Similarity Comparison ──
  t0 = nowMs();
  const isMatch = cosineCompare(liveEmbedding, qrData.faceEmbedding, 0.5);
  times.p3_face_compare.push(nowMs() - t0);

  if (!isMatch) throw new Error("Face comparison failed (should not happen in benchmark)");

  // ── Phase 4: Key Derivation (SHA-256 → BN scalar → S=k·G) ──
  t0 = nowMs();
  const kHash = sha256Hash(qrData.faceHash + qrData.salt);
  let k = new BN(kHash, 16).umod(ec.curve.n);
  if (k.isZero()) k = k.iaddn(1);
  ec.g.mul(k); // compute public point
  times.p4_key_derive.push(nowMs() - t0);

  // ── Phase 5: LRS Sign ──
  t0 = nowMs();
  // Derive a vectorHash as the message (what the live system does)
  const dummyMsg = sha256Hash("benchmark_vector_" + iter);
  const signature = suppress(() => lrs.sign(SIGNER_K, RING_POINTS, SIGNER_IDX, dummyMsg));
  times.p5_lrs_sign.push(nowMs() - t0);

  // ── Phase 6: LRS Verify (local) ──
  t0 = nowMs();
  const sigValid = suppress(() => lrs.verify(signature, RING_POINTS, dummyMsg));
  times.p6_lrs_verify.push(nowMs() - t0);

  if (!sigValid) throw new Error("LRS verify failed (bug in benchmark)");

  // ── Phase 7: ElGamal Vector Encrypt + ZKP ──
  t0 = nowMs();
  const encVector = suppress(() =>
    Array.from({ length: CANDIDATES }, (_, i) => {
      const voteVal = i === VOTE_CHOICE ? 1 : 0;
      const cipher  = homomorphic.encrypt(elgamalKp.publicKey, voteVal);
      const proof   = homomorphic.proveValidVote(elgamalKp.publicKey, cipher, voteVal, cipher.r);
      const ser     = homomorphic.serializeCiphertext(cipher);
      ser.validityProof = proof;
      return ser;
    })
  );
  times.p7_elgamal_vector.push(nowMs() - t0);

  // ── Phase 8: Fabric Submit ──
  t0 = nowMs();
  await fabricSubmit(signature, RING_POINTS.map(p => ({ x: p.getX().toString(16), y: p.getY().toString(16) })), encVector);
  times.p8_fabric_submit.push(nowMs() - t0);

  process.stdout.write(`\r  Iteration ${++iter}/${ITERS} complete`);
}

(async () => {
  for (let i = 0; i < ITERS; i++) await runIter();

  console.log("\n\n" + "─".repeat(70));
  console.log(`  E2E Phase-by-Phase Latency Summary (ring_size=${RING_SIZE}, candidates=${CANDIDATES})`);
  console.log("─".repeat(70));

  const PHASE_LABELS = {
    p1_qr_decrypt:     "P1  QR Decode + PBKDF2 + AES",
    p2_face_embed:     "P2  Face Embedding (Python API)",
    p3_face_compare:   "P3  Cosine Similarity Compare",
    p4_key_derive:     "P4  Key Derivation (SHA-256→k→k·G)",
    p5_lrs_sign:       "P5  Ring Signature Sign",
    p6_lrs_verify:     "P6  Ring Signature Verify (local)",
    p7_elgamal_vector: "P7  ElGamal Vector + ZKP",
    p8_fabric_submit:  "P8  Blockchain Submit (Fabric)",
  };

  const statsAll = {};
  let totalMean = 0;

  console.log(`\n  ${"Phase".padEnd(40)} ${"Mean(ms)".padStart(10)} ${"±SD".padStart(10)} ${"P95".padStart(10)}`);
  console.log(`  ${"─".repeat(70)}`);

  for (const [key, label] of Object.entries(PHASE_LABELS)) {
    const st = calcStats(times[key]);
    statsAll[key] = { label, stats: st };
    totalMean += st.mean;
    const note = LIVE_FABRIC || !["p2_face_embed", "p8_fabric_submit"].includes(key) ? "" : " *";
    console.log(`  ${label.padEnd(40)} ${String(st.mean).padStart(10)} ${("±"+st.sd).padStart(10)} ${String(st.p95).padStart(10)}${note}`);
  }

  console.log(`  ${"─".repeat(70)}`);
  console.log(`  ${"TOTAL".padEnd(40)} ${String(totalMean.toFixed(3)).padStart(10)}`);
  console.log(`\n  * = simulated latency; run with --live flag for measured network latency`);
  console.log("─".repeat(70) + "\n");

  // Save results
  const results = {
    meta: {
      date: new Date().toISOString(),
      iterations: ITERS,
      ring_size: RING_SIZE,
      candidates: CANDIDATES,
      live_fabric: LIVE_FABRIC
    },
    phases: statsAll,
    total_mean_ms: +totalMean.toFixed(3)
  };

  fs.writeFileSync("e2e_results.json", JSON.stringify(results, null, 2));
  console.log("  ✓ Saved e2e_results.json\n  → Next run: python e2e_plot.py\n");
})();
