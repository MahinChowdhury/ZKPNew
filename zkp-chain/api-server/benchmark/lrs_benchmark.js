/**
 * LRS Benchmark Runner
 * Place this file in the same folder as your lrs.js
 *
 * Step 1:  node lrs_benchmark.js
 * Step 2:  python lrs_plot.py
 *
 * Requirements:
 *   npm install elliptic bn.js
 *   pip install matplotlib numpy
 */

const crypto = require("crypto");
const EC = require("elliptic").ec;
const BN = require("bn.js");
const fs = require("fs");
const { sign, verify, linkTagsEqual } = require("../crypto/lrs");

const ec = new EC("secp256k1");

// ── utils ─────────────────────────────────────────────────────────────────────

function genRing(n) {
  const pairs = Array.from({ length: n }, () => {
    const priv = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
    return { priv, pub: ec.g.mul(priv) };
  });
  return { ring: pairs.map(p => p.pub), privs: pairs.map(p => p.priv) };
}

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function calcStats(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const sd = Math.sqrt(arr.reduce((a, v) => a + (v - mean) ** 2, 0) / arr.length);
  return {
    mean: +mean.toFixed(4),
    sd:   +sd.toFixed(4),
    min:  +s[0].toFixed(4),
    max:  +s[s.length - 1].toFixed(4),
    p95:  +s[Math.ceil(0.95 * s.length) - 1].toFixed(4),
    p99:  +s[Math.ceil(0.99 * s.length) - 1].toFixed(4),
  };
}

function silent(fn) {
  const o = { log: console.log, error: console.error };
  console.log = () => {}; console.error = () => {};
  try { return fn(); } finally { Object.assign(console, o); }
}

// ── config ────────────────────────────────────────────────────────────────────

const RING_SIZES = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1000];
const ITERS      = 10;   // reduced from 30 — large rings are slow
const TP_MS      = 4000;
const SIM_VOTERS = [5, 10, 20, 50, 100];
// Simulation uses ring_size = voters (realistic scaling)

const results = {
  meta: { date: new Date().toISOString(), node: process.version, curve: "secp256k1", iterations: ITERS },
  latency:     [],
  sig_size:    [],
  throughput:  [],
  memory:      [],
  linkability: {},
  simulation:  [],
};

// ── 1. Latency ────────────────────────────────────────────────────────────────

console.log("\n[1/5] Latency by ring size...");
for (const n of RING_SIZES) {
  const { ring, privs } = genRing(n);
  const idx = Math.floor(n / 2);
  const msg = "VOTE:CandidateA";
  const signT = [], verifyT = [];
  let lastSig;

  for (let i = 0; i < ITERS; i++) {
    const t0 = nowMs();
    const sig = silent(() => sign(privs[idx], ring, idx, msg));
    signT.push(nowMs() - t0);
    lastSig = sig;

    const t1 = nowMs();
    const ok = silent(() => verify(sig, ring, msg));
    verifyT.push(nowMs() - t1);
    if (!ok) throw new Error(`Verify failed n=${n}`);
  }

  results.latency.push({ n, sign: calcStats(signT), verify: calcStats(verifyT) });
  results.sig_size.push({
    n,
    json_bytes:    Buffer.byteLength(JSON.stringify(lastSig)),
    compact_bytes: 32 + 32 * n + 64,
  });

  console.log(`  n=${String(n).padEnd(3)} sign=${calcStats(signT).mean.toFixed(2)}ms  verify=${calcStats(verifyT).mean.toFixed(2)}ms`);
}

// ── 2. Throughput ─────────────────────────────────────────────────────────────

console.log("\n[2/5] Throughput (ops/sec)...");
for (const n of RING_SIZES) {
  const { ring, privs } = genRing(n);
  const msg = "VOTE:throughput";

  let sc = 0;
  const tend = Date.now() + TP_MS;
  while (Date.now() < tend) { silent(() => sign(privs[0], ring, 0, msg)); sc++; }

  const sig = silent(() => sign(privs[0], ring, 0, msg));
  let vc = 0;
  const vend = Date.now() + TP_MS;
  while (Date.now() < vend) { silent(() => verify(sig, ring, msg)); vc++; }

  const sign_ops = +(sc / (TP_MS / 1000)).toFixed(2);
  const verify_ops = +(vc / (TP_MS / 1000)).toFixed(2);
  results.throughput.push({ n, sign_ops, verify_ops });
  console.log(`  n=${String(n).padEnd(3)} sign=${sign_ops} ops/s  verify=${verify_ops} ops/s`);
}

// ── 3. Memory ─────────────────────────────────────────────────────────────────

console.log("\n[3/5] Memory usage...");
for (const n of RING_SIZES) {
  const { ring, privs } = genRing(n);
  const msg = "VOTE:memory";
  if (global.gc) global.gc();
  const before = process.memoryUsage().heapUsed / 1024 / 1024;
  silent(() => sign(privs[0], ring, 0, msg));
  const after = process.memoryUsage().heapUsed / 1024 / 1024;
  results.memory.push({
    n,
    before_mb: +before.toFixed(3),
    after_mb:  +after.toFixed(3),
    delta_mb:  +(after - before).toFixed(3),
  });
  console.log(`  n=${String(n).padEnd(3)} heap delta=${+(after - before).toFixed(3)} MB`);
}

// ── 4. Linkability (double-vote detection) ────────────────────────────────────

console.log("\n[4/5] Linkability detection...");
{
  const LINK_ITERS = 500;
  const { ring, privs } = genRing(5);
  const sig1 = silent(() => sign(privs[0], ring, 0, "VOTE:A"));
  const sig2 = silent(() => sign(privs[0], ring, 0, "VOTE:B")); // same voter, diff vote
  const sig3 = silent(() => sign(privs[1], ring, 1, "VOTE:A")); // different voter

  const times = [];
  let tp = 0, tn = 0;
  for (let i = 0; i < LINK_ITERS; i++) {
    const t0 = nowMs();
    const same = linkTagsEqual(sig1.linkTag, sig2.linkTag); // must be true
    const diff = linkTagsEqual(sig1.linkTag, sig3.linkTag); // must be false
    times.push(nowMs() - t0);
    if (same) tp++;
    if (!diff) tn++;
  }

  results.linkability = {
    iterations:      LINK_ITERS,
    true_positives:  tp,
    true_negatives:  tn,
    accuracy_pct:    +((tp + tn) / (LINK_ITERS * 2) * 100).toFixed(2),
    check_time:      calcStats(times),
  };
  console.log(`  Accuracy=${results.linkability.accuracy_pct}%  mean check=${calcStats(times).mean.toFixed(5)}ms`);
}

// ── 5. End-to-end voting simulation ──────────────────────────────────────────

console.log("\n[5/5] Voting simulation (ring_size = voters)...");
for (const numVoters of SIM_VOTERS) {
  const { ring, privs } = genRing(numVoters);
  const candidates = ["CandidateA", "CandidateB", "CandidateC"];
  const usedTags = [];
  let signTotal = 0, verifyTotal = 0, valid = 0, rejected = 0;

  const wallStart = nowMs();
  for (let v = 0; v < numVoters; v++) {
    const idx = v;
    const msg = `VOTE:${candidates[v % 3]}:election2025`;

    const t0 = nowMs();
    const sig = silent(() => sign(privs[idx], ring, idx, msg));
    signTotal += nowMs() - t0;

    const t1 = nowMs();
    const ok = silent(() => verify(sig, ring, msg));
    verifyTotal += nowMs() - t1;

    if (!ok) { rejected++; continue; }
    if (usedTags.some(t => linkTagsEqual(t, sig.linkTag))) { rejected++; continue; }
    usedTags.push(sig.linkTag);
    valid++;
  }
  const wallMs = nowMs() - wallStart;

  results.simulation.push({
    voters:         numVoters,
    ring_size:      numVoters,
    valid_votes:    valid,
    rejected:       rejected,
    total_ms:       +wallMs.toFixed(2),
    votes_per_sec:  +(numVoters / wallMs * 1000).toFixed(2),
    avg_sign_ms:    +(signTotal / numVoters).toFixed(4),
    avg_verify_ms:  +(verifyTotal / numVoters).toFixed(4),
  });
  console.log(`  voters=${numVoters}  ring=${numVoters}  valid=${valid}  total=${wallMs.toFixed(0)}ms  ${+(numVoters/wallMs*1000).toFixed(1)} votes/s`);
}

// ── write JSON ────────────────────────────────────────────────────────────────

fs.writeFileSync("lrs_results.json", JSON.stringify(results, null, 2));
console.log("\n✓ Saved lrs_results.json — now run:  python lrs_plot.py\n");