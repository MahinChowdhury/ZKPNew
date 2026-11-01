// ============================================================
// bench_fabric.mjs — costs on the LIVE Fabric test network
//
// Unlike bench_client.mjs (in-memory stub), every transaction here goes
// through the Fabric gateway SDK to the deployed chaincode: endorsement on
// both organisations' peers, ordering, validation and commit.
//
// Measures, for one ballot with a 2-of-3 trustee key:
//   * key generation (registerBallot, 3 dealings, finalizeBallotKey);
//   * voter registration (one transaction per voter, sequential);
//   * castVote latency, sequential (submit → committed);
//   * castVote under concurrent submission: throughput and MVCC conflicts;
//   * close + threshold decryption + on-chain tally verification.
// Proofs are generated beforehand with the voter client (not timed here;
// bench_client.mjs reports client costs).
//
// Usage (from api-server/, network up, current chaincode deployed, wallet
// enrolled with enrollAdmin.js + enrollUser.js):
//   node benchmark/bench_fabric.mjs [voters=40] [concurrency=10]
// Output: results/fabric_results.json
// ============================================================

import { createRequire } from "module";
import path from "path";
import fs from "fs";
import os from "os";
import crypto from "crypto";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API = path.join(__dirname, "..");
const FabricClient = require(path.join(API, "fabric-client"));
const threshold = require(path.join(API, "crypto", "threshold"));
const { loadSigner, attest } = require(path.join(API, "sensor", "attest-core"));
const client = await import(path.join(API, "..", "frontend", "src", "crypto", "voterClient.js"));

const VOTERS = parseInt(process.argv[2] || "40", 10);
const CONCURRENCY = parseInt(process.argv[3] || "10", 10);
const OPTIONS = 3;
const ARTIFACTS = {
  wasm: path.join(API, "circuits", "face_auth_js", "face_auth.wasm"),
  zkey: path.join(API, "circuits", "face_auth.zkey"),
};

const now = () => performance.now();
async function timed(fn) {
  const t = now();
  const r = await fn();
  return [now() - t, r];
}
function stats(xs) {
  const n = xs.length;
  const mean = xs.reduce((a, b) => a + b, 0) / n;
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(1, n - 1));
  const s = [...xs].sort((a, b) => a - b);
  const r1 = (x) => Math.round(x * 10) / 10;
  return { n, mean: r1(mean), sd: r1(sd), ci95: r1(1.96 * sd / Math.sqrt(n)), p50: r1(s[Math.floor(n / 2)]), p95: r1(s[Math.min(n - 1, Math.floor(0.95 * n))]), min: r1(s[0]), max: r1(s[n - 1]) };
}
const unit = (d = 128) => { const v = Array.from({ length: d }, () => Math.random() * 2 - 1); const k = Math.hypot(...v); return v.map((x) => x / k); };
const perturb = (v, s = 0.05) => { const w = v.map((x) => x + s * (Math.random() * 2 - 1)); const k = Math.hypot(...w); return w.map((x) => x / k); };
const quiet = async (fn) => { const l = console.log, w = console.warn; console.log = console.warn = () => {}; try { return await fn(); } finally { console.log = l; console.warn = w; } };

const fc = new FabricClient();
await quiet(() => fc.connect());
const run = Date.now().toString(36);
const ballotId = `live-${run}`;
const results = {
  date: new Date().toISOString(),
  host: { cpu: os.cpus()[0].model, threads: os.cpus().length, node: process.version },
  network: "Fabric test-network: 2 orgs x 1 peer, CouchDB, 1 orderer, endorsement by both orgs",
  voters: VOTERS, concurrency: CONCURRENCY,
};

// ---------- capture device ----------
const device = await loadSigner();
try {
  await quiet(() => fc.registerSensor(device.publicKey.ax, device.publicKey.ay));
} catch (e) {
  if (!/already/i.test(e.message)) throw e;
}

// ---------- 2-of-3 trustee key generation ----------
console.log("Key generation...");
const trustees = [1, 2, 3].map((i) => new threshold.Trustee(i));
const kg = { dealings: [] };
[kg.registerBallot] = await timed(() => quiet(() => fc.registerBallot(ballotId, OPTIONS, trustees.map((t) => t.publicKey), 2)));
const dealings = trustees.map((t) => t.deal(ballotId, 2, 3));
for (const t of trustees) {
  const d = dealings[t.index - 1];
  const [ms] = await timed(() => quiet(() => fc.submitDealing(ballotId, t.index, d.commitments, d.sig)));
  kg.dealings.push(ms);
}
for (const r of trustees) {
  for (const d of trustees) {
    if (r.receive(ballotId, d.index, dealings[d.index - 1].commitments, dealings[d.index - 1].shares[r.index])) {
      throw new Error("unexpected inconsistent share");
    }
  }
}
const [finMs, fin] = await timed(() => quiet(() => fc.finalizeBallotKey(ballotId)));
kg.finalizeBallotKey = finMs;
trustees.forEach((t) => t.finalize(fin.qual));
results.keygen = {
  registerBallotMs: Math.round(kg.registerBallot),
  dealingMs: stats(kg.dealings),
  finalizeMs: Math.round(kg.finalizeBallotKey),
  totalMs: Math.round(kg.registerBallot + kg.dealings.reduce((a, b) => a + b, 0) + kg.finalizeBallotKey),
};
console.log(results.keygen);
const ballot = await fc.getBallot(ballotId);

// ---------- registration ----------
console.log(`Registering ${VOTERS} voters...`);
const voters = [];
const regT = [];
for (let i = 0; i < VOTERS; i++) {
  const reading = unit();
  const credential = await client.createCredential("face", client.toTemplate("face", reading));
  const nidHash = crypto.createHash("sha256").update(`${ballotId}-voter-${i}`).digest("hex");
  const [ms] = await timed(() => quiet(() => fc.registerUser(nidHash, credential.commitment)));
  regT.push(ms);
  voters.push({ reading, credential });
}
results.register = stats(regT);
console.log("register", results.register);

// ---------- votes, proved client-side beforehand ----------
console.log("Proving votes (client side, not timed)...");
const commitments = await quiet(() => fc.getCommitments());
const sensors = await quiet(() => fc.getSensors());
const txs = [];
for (let i = 0; i < VOTERS; i++) {
  const v = voters[i];
  const session = await client.startVoteSession(v.credential, ballot);
  const attestation = await attest(device, { mode: "face", reading: perturb(v.reading), electionId: session.electionId, sessionCommit: session.sessionCommit });
  txs.push(await quiet(() => client.prepareVote({
    credential: v.credential, session, attestation, sensors, ballot, choiceIndex: i % OPTIONS, commitments, artifacts: ARTIFACTS,
  })));
}
const submit = (tx) => fc.castVote(tx.proof, tx.publicSignals, String(tx.nullifier), tx.encryptedBallot, ballotId, "face");

// Sequential: latency of one vote from submission to commit
const half = Math.floor(VOTERS / 2);
const seq = [];
for (const tx of txs.slice(0, half)) {
  const [ms] = await timed(() => quiet(() => submit(tx)));
  seq.push(ms);
}
results.castVoteSequential = stats(seq);
console.log("castVote sequential", results.castVoteSequential);

// Concurrent: CONCURRENCY submissions in flight at a time
const rest = txs.slice(half);
const lat = [];
const errors = {};
let ok = 0;
const t0 = now();
for (let i = 0; i < rest.length; i += CONCURRENCY) {
  const batch = rest.slice(i, i + CONCURRENCY);
  const settled = await quiet(() => Promise.allSettled(batch.map(async (tx) => {
    const [ms] = await timed(() => submit(tx));
    lat.push(ms);
  })));
  for (const s of settled) {
    if (s.status === "fulfilled") ok++;
    else {
      const k = (s.reason?.message || String(s.reason)).split("\n")[0].slice(0, 100);
      errors[k] = (errors[k] || 0) + 1;
    }
  }
}
const wall = now() - t0;
results.castVoteConcurrent = {
  submitted: rest.length, committed: ok, failed: rest.length - ok, errors,
  wallMs: Math.round(wall), throughputTps: Math.round((ok / (wall / 1000)) * 100) / 100,
  latency: lat.length ? stats(lat) : null,
};
console.log("castVote concurrent", results.castVoteConcurrent);

// ---------- close, threshold decryption, on-chain tally check ----------
const [closeMs] = await timed(() => quiet(() => fc.closeBallot(ballotId)));
const votes = await quiet(() => fc.getAllVotes(ballotId));
const sums = threshold.aggregate(votes.map((v) => v.encryptedVote), OPTIONS);
const [decMs, tally] = await timed(async () => threshold.decryptTally(ballotId, sums, trustees.slice(0, 2), votes.length));
const [pubMs, pub] = await timed(() => quiet(() => fc.publishTally(ballotId, tally)));
const expected = [0, 1, 2].map((j) => txs.filter((_, i) => i % OPTIONS === j).length);
results.tally = {
  numVotes: pub.numVotes, totals: pub.totals,
  closeMs: Math.round(closeMs), thresholdDecryptMs: Math.round(decMs), publishTallyMs: Math.round(pubMs),
  totalsMatchCommittedVotes: pub.totals.reduce((a, b) => a + b, 0) === votes.length,
};
console.log("tally", results.tally, "expected if all committed:", expected);

const out = path.join(API, "results", "fabric_results.json");
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(results, null, 2));
console.log("→", out);
await quiet(() => fc.disconnect());
process.exit(0);
