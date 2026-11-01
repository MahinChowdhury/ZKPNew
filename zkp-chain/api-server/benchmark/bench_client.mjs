// ============================================================
// bench_client.mjs — latency of the deployed (client-side, attested) protocol
//
// Measures, on the production code paths:
//   client   voterClient.prepareVote phases (Merkle paths, ballot
//            encryption, witness, Groth16 prove) — snarkjs WASM, i.e. the
//            same prover the browser runs
//   device   EdDSA attestation signing (sensor/attest-core.js)
//   ledger   chaincode castVote (in-memory Fabric stub), plus its two
//            dominant parts measured alone: Groth16 verify, ballot proofs
//   scaling  client Merkle-path and castVote cost vs electorate size N
//   tally    homomorphic tally of M ballots (aggregate + decrypt + DLEQ)
//
// Usage (from api-server/):  node benchmark/bench_client.mjs [runs]
// Output: results/latency_results.json
// ============================================================

import { createRequire } from "module";
import path from "path";
import fs from "fs";
import os from "os";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API = path.join(__dirname, "..");
const snarkjs = require("snarkjs");
const h = require(path.join(API, "attacks", "soundness", "harness"));
const homomorphic = require(path.join(API, "crypto", "homomorphic"));
const threshold = require(path.join(API, "crypto", "threshold"));
const { loadSigner, attest } = require(path.join(API, "sensor", "attest-core"));
const client = await import(path.join(API, "..", "frontend", "src", "crypto", "voterClient.js"));

const RUNS = parseInt(process.argv[2] || "20", 10);
const N_MAIN = 1000;                    // electorate for the per-phase runs
const N_SCALE = [10, 100, 1000, 5000, 20000];  // electorate sweep
const M_TALLY = [100, 1000];            // ballots tallied
const CIRC = path.join(API, "circuits");
const ARTIFACTS = {
  face: { wasm: path.join(CIRC, "face_auth_js", "face_auth.wasm"), zkey: path.join(CIRC, "face_auth.zkey") },
  iris: { wasm: path.join(CIRC, "iris_auth_js", "iris_auth.wasm"), zkey: path.join(CIRC, "iris_auth.zkey") },
};
const VKEY = {
  face: JSON.parse(fs.readFileSync(path.join(CIRC, "verification_key.json"))),
  iris: JSON.parse(fs.readFileSync(path.join(CIRC, "iris_verification_key.json"))),
};

const now = () => performance.now();
function stats(xs) {
  const n = xs.length, mean = xs.reduce((a, b) => a + b, 0) / n;
  const sd = n > 1 ? Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1)) : 0;
  const r = (v) => Math.round(v * 10) / 10;
  return { n, mean: r(mean), sd: r(sd), ci95: r(1.96 * sd / Math.sqrt(n)), min: r(Math.min(...xs)), max: r(Math.max(...xs)) };
}
const unit = (d = 128) => { const v = Array.from({ length: d }, () => Math.random() * 2 - 1); const k = Math.hypot(...v); return v.map((x) => x / k); };
const perturb = (v, s = 0.05) => { const w = v.map((x) => x + s * (Math.random() * 2 - 1)); const k = Math.hypot(...w); return w.map((x) => x / k); };
const irisReading = () => ({ irisCode: Array.from({ length: 4096 }, () => (Math.random() < 0.5 ? 1 : 0)), noiseMask: Array(4096).fill(1) });
const irisRecapture = (r) => ({ irisCode: r.irisCode.map((b) => (Math.random() < 0.06 ? b ^ 1 : b)), noiseMask: r.noiseMask });

// ------------------------------------------------------------
// A ledger with `n` enrolled voters per modality; the first `real` of
// each are genuine credentials, the rest random field elements (the
// commitment list is all the protocol ever reads).
// ------------------------------------------------------------
async function makeWorld(n, real) {
  const IdentityContract = require(path.join(API, "..", "chaincode", "identity", "lib", "identityContract.js"));
  const contract = new IdentityContract();
  const { ctx, state } = h.makeLedger();
  const voters = { face: [], iris: [] };
  for (const mode of ["face", "iris"]) {
    for (let i = 0; i < real; i++) {
      const reading = mode === "face" ? unit() : irisReading();
      voters[mode].push({ reading, credential: await client.createCredential(mode, client.toTemplate(mode, reading)) });
    }
    const commitments = voters[mode].map((v) => v.credential.commitment);
    for (let i = real; i < n; i++) commitments.push(h.fieldStr(BigInt("0x" + Buffer.from(crypto.getRandomValues(new Uint8Array(31))).toString("hex"))));
    const key = mode === "face" ? "GLOBAL_COMMITMENTS" : "GLOBAL_IRIS_COMMITMENTS";
    state.set(key, Buffer.from(JSON.stringify({ commitments: commitments.map((value) => ({ value })), docType: "commitments" })));
    // Build the incremental tree now (as registration would have), so votes
    // measure the steady state rather than the one-time migration
    await contract._treeState(ctx, mode);
  }
  const device = await loadSigner();
  await h.quiet(() => contract.registerSensor(ctx, device.publicKey.ax, device.publicKey.ay));
  // 2-of-3 trustee key, generated through the chaincode
  const ballotId = `bench-${n}`;
  const { trustees, record: ballot } = await h.setupBallot(contract, ctx, ballotId, 3);
  return { contract, ctx, state, voters, device, trustees, ballot };
}

async function oneVote(w, mode, v) {
  const t = {};
  let t0 = now();
  const session = await client.startVoteSession(v.credential, w.ballot);
  t.session = now() - t0;
  const live = mode === "face" ? perturb(v.reading) : irisRecapture(v.reading);
  t0 = now();
  const attestation = await attest(w.device, { mode, reading: live, electionId: session.electionId, sessionCommit: session.sessionCommit });
  t.deviceSign = now() - t0;
  const commitments = JSON.parse(await h.quiet(() => w.contract[mode === "face" ? "getCommitments" : "getIrisCommitments"](w.ctx)));
  const sensors = JSON.parse(await h.quiet(() => w.contract.getSensors(w.ctx)));
  t0 = now();
  const tx = await client.prepareVote({
    credential: v.credential, session, attestation, sensors, ballot: w.ballot, choiceIndex: Math.floor(Math.random() * 3),
    commitments, artifacts: ARTIFACTS[mode], timings: t,
  });
  t.clientTotal = now() - t0;

  t0 = now();
  const ok = await snarkjs.groth16.verify(VKEY[mode], tx.publicSignals, tx.proof);
  t.groth16Verify = now() - t0;
  if (!ok) throw new Error("proof failed to verify");

  t0 = now();
  await h.quiet(() => w.contract.castVote(w.ctx, JSON.stringify(tx.proof), JSON.stringify(tx.publicSignals),
    tx.nullifier, JSON.stringify(tx.encryptedBallot), tx.ballotId, mode));
  t.castVote = now() - t0;
  return t;
}

const results = {
  date: new Date().toISOString(),
  host: { cpu: os.cpus()[0].model, threads: os.cpus().length, node: process.version, prover: "snarkjs WASM (same as browser)" },
  runs: RUNS, electorate: N_MAIN, phases: {}, scaling: {}, tally: {},
};

// ---------------- per-phase latency at N = N_MAIN ----------------
console.log(`Per-phase latency: ${RUNS} votes per modality, N = ${N_MAIN}`);
const w = await makeWorld(N_MAIN, RUNS + 1);
for (const mode of ["face", "iris"]) {
  await oneVote(w, mode, w.voters[mode][RUNS]); // warm-up (WASM compile, key load)
  const samples = [];
  for (let i = 0; i < RUNS; i++) samples.push(await oneVote(w, mode, w.voters[mode][i]));
  results.phases[mode] = Object.fromEntries(Object.keys(samples[0]).map((k) => [k, stats(samples.map((s) => s[k]))]));
  console.log(mode, JSON.stringify(Object.fromEntries(Object.entries(results.phases[mode]).map(([k, v]) => [k, v.mean]))));
}

// ---------------- scaling with electorate size ----------------
console.log("Scaling with N");
for (const n of N_SCALE) {
  const ws = await makeWorld(n, 4);
  const runs = [];
  for (let i = 0; i < 3; i++) runs.push(await oneVote(ws, "face", ws.voters.face[i]));
  results.scaling[n] = {
    clientMerkle: stats(runs.map((r) => r.merklePaths)),
    prove: stats(runs.map((r) => r.prove)),
    castVote: stats(runs.map((r) => r.castVote)),
  };
  console.log(n, results.scaling[n].clientMerkle.mean, results.scaling[n].prove.mean, results.scaling[n].castVote.mean);
}

// ---------------- tally ----------------
console.log("Tally");
for (const m of M_TALLY) {
  // Fresh ledger: 2-of-3 trustee key generation through the chaincode
  const { ctx: tctx, state: tstate } = h.makeLedger();
  const tk = now();
  const tb = await h.setupBallot(w.contract, tctx, "tally-bench", 3);
  const tKeygen = now() - tk;
  const pk = homomorphic.deserializeCiphertext({ c1: tb.record.publicKey, c2: tb.record.publicKey }).c1;
  const ballots = Array.from({ length: m }, (_, i) =>
    ({ nullifier: String(i + 1), enc: homomorphic.encryptBallot(pk, 3, i % 3, "tally-bench", String(i + 1)) }));

  // Off-chain: re-verify every ballot and aggregate
  const t0 = now();
  for (const b of ballots) {
    const cts = b.enc.ciphertexts.map((c) => homomorphic.deserializeCiphertext(c));
    const okProofs = b.enc.ciphertexts.every((c, j) => homomorphic.verifyValidVote(pk, cts[j], c.validityProof, homomorphic.optionContext("tally-bench", b.nullifier, j)))
      && homomorphic.verifySumIsOne(pk, cts, b.enc.sumProof, homomorphic.sumContext("tally-bench", b.nullifier));
    if (!okProofs) throw new Error("ballot proof failed");
  }
  const sums = threshold.aggregate(ballots.map((b) => b.enc), 3);
  const tVerifyAgg = now() - t0;

  // t trustees: partial decryptions with proofs, Lagrange combination, BSGS
  const t1 = now();
  const tally = threshold.decryptTally("tally-bench", sums, tb.trustees.slice(0, tb.record.threshold), m);
  const tDecrypt = now() - t1;

  // On-chain: the chaincode recomputes the aggregates from the stored
  // ballots and checks t partial-decryption proofs per option
  ballots.forEach((b, i) => tstate.set(`VOTE_tb_${i}`, Buffer.from(JSON.stringify({
    docType: "vote", voteId: `VOTE_tb_${i}`, ballotId: "tally-bench", nullifier: b.nullifier, encryptedVote: b.enc,
  }))));
  await h.quiet(() => w.contract.closeBallot(tctx, "tally-bench"));
  const t2 = now();
  const pub = JSON.parse(await h.quiet(() => w.contract.publishTally(tctx, "tally-bench", JSON.stringify(tally))));
  const tPublish = now() - t2;

  results.tally[m] = {
    keygenMs: Math.round(tKeygen), verifyAndAggregateMs: Math.round(tVerifyAgg),
    thresholdDecryptMs: Math.round(tDecrypt), publishTallyMs: Math.round(tPublish),
    threshold: `${tb.record.threshold}-of-${tb.trustees.length}`, totals: pub.totals,
  };
  console.log(m, results.tally[m]);
}

const out = path.join(API, "results", "latency_results.json");
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(results, null, 2));
console.log("→", out);
