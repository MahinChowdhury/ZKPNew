/**
 * Homomorphic Encryption Benchmark Runner
 * Place this file in the api-server/crypto directory.
 *
 * Measures:
 * 1. Base crypto operations latency (encrypt, decrypt, homomorphic add)
 * 2. Baby-step Giant-step (BSGS) discrete log latency vs max voters (N)
 * 3. Ciphertext sizes (JSON vs Compact)
 * 4. ZKP proof generation and verification latency
 */

const crypto = require("crypto");
const fs = require("fs");
const homomorphic = require("./homomorphic");
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

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
  const o = { log: console.log, error: console.error, warn: console.warn };
  console.log = () => {}; console.error = () => {}; console.warn = () => {};
  try { return fn(); } finally { Object.assign(console, o); }
}

const ITERS = 100;
const BSGS_N_VALUES = [10, 50, 100, 500, 1000, 5000, 10000];

const results = {
  meta: { date: new Date().toISOString(), node: process.version, curve: "secp256k1", iterations: ITERS },
  base_latency: {},
  bsgs_latency: [],
  zkp_latency: {},
  sizes: {}
};

console.log(`\n=== Homomorphic ElGamal Benchmarks (${ITERS} iters) ===`);

const keypair = silent(() => homomorphic.generateKeypair());

// 1. Base Latency
console.log("\n[1/4] Base Cryptographic Operations...");
const enc_times = [];
const dec_times = [];
const add_times = [];
let sample_ciphertext = null;
let sample_r = null;

for (let i = 0; i < ITERS; i++) {
  const t0 = nowMs();
  const ct1 = silent(() => homomorphic.encrypt(keypair.publicKey, 1));
  enc_times.push(nowMs() - t0);
  
  if (i === 0) {
    sample_ciphertext = ct1;
    sample_r = ct1.r;
  }

  const ct2 = silent(() => homomorphic.encrypt(keypair.publicKey, 1));
  
  const t1 = nowMs();
  const sum_ct = silent(() => homomorphic.addCiphertexts(ct1, ct2));
  add_times.push(nowMs() - t1);

  const t2 = nowMs();
  const decryptedM = silent(() => homomorphic.decrypt(keypair.privateKey, sum_ct));
  dec_times.push(nowMs() - t2);
}

results.base_latency = {
  encrypt: calcStats(enc_times),
  homomorphic_add: calcStats(add_times),
  decrypt_to_point: calcStats(dec_times)
};
console.log(`  Encrypt:  ${results.base_latency.encrypt.mean.toFixed(3)} ms`);
console.log(`  Homo Add: ${results.base_latency.homomorphic_add.mean.toFixed(3)} ms`);
console.log(`  Decrypt:  ${results.base_latency.decrypt_to_point.mean.toFixed(3)} ms`);

// 2. BSGS Latency
console.log("\n[2/4] Baby-step Giant-step (Discrete Log) vs Max Voters (N)...");
for (const n of BSGS_N_VALUES) {
  // Simulate a tally of n/2 votes
  const targetVoteCount = Math.floor(n / 2);
  const M = silent(() => homomorphic.encodeVote(targetVoteCount));
  
  const bsgs_times = [];
  // For BSGS, use fewer iterations as n grows, since it can take a bit longer
  const bsgsIters = n > 1000 ? 10 : 30;
  for (let i = 0; i < bsgsIters; i++) {
    const t0 = nowMs();
    const v = silent(() => homomorphic.solveDiscreteLog(M, n));
    bsgs_times.push(nowMs() - t0);
    if (v !== targetVoteCount) throw new Error("BSGS failed");
  }
  
  results.bsgs_latency.push({
    max_voters: n,
    actual_votes: targetVoteCount,
    stats: calcStats(bsgs_times)
  });
  console.log(`  N=${String(n).padEnd(5)} -> ${calcStats(bsgs_times).mean.toFixed(3)} ms (target vote=${targetVoteCount})`);
}

// 3. ZKP Latency (Disjunctive Chaum-Pedersen)
console.log("\n[3/4] Zero-Knowledge Proof (Vote Validity)...");
const zkp_prove = [];
const zkp_verify = [];

for (let i = 0; i < ITERS; i++) {
  const voteVal = i % 2; // alternate 0 and 1
  const ct = silent(() => homomorphic.encrypt(keypair.publicKey, voteVal));
  
  const t0 = nowMs();
  const proof = silent(() => homomorphic.proveValidVote(keypair.publicKey, ct, voteVal, ct.r));
  zkp_prove.push(nowMs() - t0);
  
  const t1 = nowMs();
  const valid = silent(() => homomorphic.verifyValidVote(keypair.publicKey, ct, proof));
  zkp_verify.push(nowMs() - t1);
  
  if (!valid) throw new Error("ZKP verification failed");
}

results.zkp_latency = {
  prove: calcStats(zkp_prove),
  verify: calcStats(zkp_verify)
};
console.log(`  Prove:  ${results.zkp_latency.prove.mean.toFixed(3)} ms`);
console.log(`  Verify: ${results.zkp_latency.verify.mean.toFixed(3)} ms`);

// 4. Ciphertext Sizes
console.log("\n[4/4] Analyzing object sizes...");
const serializedCt = homomorphic.serializeCiphertext(sample_ciphertext);
const jsonStr = JSON.stringify(serializedCt);
const proofSample = silent(() => homomorphic.proveValidVote(keypair.publicKey, sample_ciphertext, 1, sample_r));

results.sizes = {
  ciphertext_json_bytes: Buffer.byteLength(jsonStr),
  ciphertext_compact_bytes: 33 * 2, // two compressed curve points (33 bytes each)
  zkp_proof_json_bytes: Buffer.byteLength(JSON.stringify(proofSample)),
  zkp_proof_compact_bytes: 33 * 4 + 32 * 4 // four points, four scalars
};
console.log(`  Ciphertext: ${results.sizes.ciphertext_json_bytes} bytes (JSON) / ${results.sizes.ciphertext_compact_bytes} bytes (Compact)`);
console.log(`  ZKP Proof:  ${results.sizes.zkp_proof_json_bytes} bytes (JSON) / ${results.sizes.zkp_proof_compact_bytes} bytes (Compact)`);

// Write results
fs.writeFileSync("homomorphic_results.json", JSON.stringify(results, null, 2));
console.log("\n✓ Saved homomorphic_results.json — next run: python homomorphic_plot.py\n");
