// ============================================================
// test_client_pipeline.mjs — client-side voting end to end (FINDINGS C5)
//
// Runs the SAME module the browser uses (frontend/src/crypto/voterClient.js)
// against the REAL register / ballot / vote / tally routes and the REAL
// chaincode with PRODUCTION keys. Fabric is an in-memory stub; biometric
// readings are synthetic (the Python service is not involved).
//
// Besides correctness it records every request body the gateway receives
// and asserts that none contains a secret key, salt, template value,
// password, or the voter's choice.
//
// Usage (from api-server/, after circuits/build_*.sh):
//   node attacks/soundness/test_client_pipeline.mjs
// ============================================================

import { createRequire } from "module";
import path from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const express = require("express");
const h = require("./harness");
const crypto = require("crypto");
const { loadSigner, attest, attestEnrollment } = require("../../sensor/attest-core");
const client = await import("../../../frontend/src/crypto/voterClient.js");

const API = path.join(__dirname, "..", "..");
const CIRCUITS = path.join(API, "circuits");
const ARTIFACTS = {
  face: { wasm: path.join(CIRCUITS, "face_auth_js", "face_auth.wasm"), zkey: path.join(CIRCUITS, "face_auth.zkey") },
  iris: { wasm: path.join(CIRCUITS, "iris_auth_js", "iris_auth.wasm"), zkey: path.join(CIRCUITS, "iris_auth.zkey") },
  enroll: { wasm: path.join(CIRCUITS, "enroll_auth_js", "enroll_auth.wasm"), zkey: path.join(CIRCUITS, "enroll_auth.zkey") },
};
const OPTIONS = ["Alice", "Bob", "Carol"];
const PASSWORD = "correct horse battery staple";

let failures = 0;
function check(name, cond, detail = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!cond) failures++;
}

// ---------- synthetic biometric readings (stand-in for model/app.py) ----------
const unit = (d = 128) => { const v = Array.from({ length: d }, () => Math.random() * 2 - 1); const n = Math.hypot(...v); return v.map((x) => x / n); };
const perturb = (v, s = 0.05) => { const w = v.map((x) => x + s * (Math.random() * 2 - 1)); const n = Math.hypot(...w); return w.map((x) => x / n); };
const irisReading = () => ({ irisCode: Array.from({ length: 4096 }, () => (Math.random() < 0.5 ? 1 : 0)), noiseMask: Array(4096).fill(1) });
const irisRecapture = (r) => ({ irisCode: r.irisCode.map((b) => (Math.random() < 0.06 ? b ^ 1 : b)), noiseMask: r.noiseMask });

// ---------- chaincode-backed Fabric client ----------
const IdentityContract = require(path.join(API, "..", "chaincode", "identity", "lib", "identityContract.js"));
const contract = new IdentityContract();
const { ctx } = h.makeLedger();
const cc = async (fn, ...args) => h.quiet(() => contract[fn](ctx, ...args));
const fabricClient = {
  registerUser: (nid, c, p, s) => cc("register", nid, c, p, s),
  registerIrisUser: (nid, c) => cc("registerIris", nid, c),
  getCommitments: async () => JSON.parse(await cc("getCommitments")),
  getIrisCommitments: async () => JSON.parse(await cc("getIrisCommitments")),
  registerBallot: (id, n, trustees, t) => cc("registerBallot", id, String(n), JSON.stringify(trustees), String(t)),
  submitDealing: (id, i, commitments, sig) => cc("submitDealing", id, String(i), JSON.stringify(commitments), sig),
  complain: (id, j, i, share, sig) => cc("complain", id, String(j), String(i), share, sig),
  finalizeBallotKey: async (id) => JSON.parse(await cc("finalizeBallotKey", id)),
  closeBallot: (id) => cc("closeBallot", id),
  publishTally: async (id, tally) => JSON.parse(await cc("publishTally", id, JSON.stringify(tally))),
  getTally: async (id) => JSON.parse(await cc("getTally", id)),
  getBallot: async (id) => JSON.parse(await cc("getBallot", id)),
  getAllVotes: async (id) => JSON.parse(await cc("getAllVotes", id)),
  hasVoted: async (n) => String(await cc("hasVoted", n)) === "true",
  registerSensor: async (ax, ay) => JSON.parse(await cc("registerSensor", ax, ay)),
  getSensors: async () => JSON.parse(await cc("getSensors")),
  castVote: async (proof, ps, nullifier, enc, ballotId, mode) => JSON.parse(await cc(
    "castVote", JSON.stringify(proof), JSON.stringify(ps), nullifier, enc ? JSON.stringify(enc) : "", ballotId, mode)),
};

// ---------- the real gateway routes ----------
const ballotRoutes = require(path.join(API, "routes", "ballot"));
const seenBodies = [];
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use((req, res, next) => {
  res.locals.fabricClient = fabricClient;
  res.locals.ballotRoutes = ballotRoutes;
  res.locals.snark = require(path.join(API, "crypto", "snark"));
  res.locals.irisSnark = require(path.join(API, "crypto", "iris-snark"));
  if (req.method === "POST") seenBodies.push({ url: req.originalUrl, body: JSON.stringify(req.body || {}) });
  next();
});
app.use("/api/v1/register", require(path.join(API, "routes", "register")));
app.use("/api/v1/sensors", require(path.join(API, "routes", "sensors")));
app.use("/api/v1/ballot", ballotRoutes);
app.use("/api/v1/tally", require(path.join(API, "routes", "tally")));
app.use("/api/v1/vote", require(path.join(API, "routes", "vote")));
const server = app.listen(0);
const BASE = `http://127.0.0.1:${server.address().port}/api/v1`;
const post = (p, body) => h.quiet(() => fetch(BASE + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) }).then((r) => r.json()));
const get = (p) => h.quiet(() => fetch(BASE + p).then((r) => r.json()));

// ---------- voter-side helpers (what the frontend does) ----------
async function registerVoter(nid, mode, reading) {
  let credential, enrollment = {};
  if (mode === "face") {
    // Supervised kiosk: signs the captured template for the NID the RA entered
    const nidHash = crypto.createHash("sha256").update(nid).digest("hex");
    const attestation = await attestEnrollment(device, { mode, reading, nidHash });
    credential = await client.createCredential(mode, attestation.template);
    const { sensors } = await get("/sensors");
    const { proof, publicSignals } = await h.quiet(() => client.proveEnrollment({
      credential, attestation, sensors, nidHash, artifacts: ARTIFACTS.enroll }));
    enrollment = { enrollProof: proof, enrollSignals: publicSignals };
  } else {
    credential = await client.createCredential(mode, client.toTemplate(mode, reading));
  }
  const sealed = await client.sealCredential(credential, PASSWORD);
  const r = await post("/register", { nidNumber: nid, biometricMode: mode, commitment: credential.commitment, ...enrollment });
  if (!r.ok) throw new Error(r.error);
  return { sealed, credential };
}

const attestorSaw = [];
async function vote(sealed, mode, liveReading, ballotId, choiceIndex) {
  const credential = await client.openCredential(sealed, PASSWORD);
  const { ballot } = await get(`/ballot/${ballotId}/chain`);
  // Session first: the capture device only ever sees sessionCommit
  const session = await client.startVoteSession(credential, ballot);
  const request = { mode, reading: liveReading, electionId: session.electionId, sessionCommit: session.sessionCommit };
  attestorSaw.push(JSON.stringify(request));
  const attestation = await attest(device, request);
  const { sensors } = await get("/sensors");
  // Public ledger data (served by GET /api/v1/commitments[/iris] in server.js)
  const list = mode === "face" ? await fabricClient.getCommitments() : await fabricClient.getIrisCommitments();
  const tx = await h.quiet(() => client.prepareVote({
    credential, session, attestation, sensors, ballot, choiceIndex, commitments: list, artifacts: ARTIFACTS[mode],
  }));
  return { ...(await post("/vote", tx)), nullifier: session.nullifier };
}

const device = await loadSigner();

try {
  // Admin: create ballot + publish its key on-chain
  const created = await post("/ballot/create", { title: "Client pipeline", options: OPTIONS });
  const ballotId = created.ballot.id;
  const setup = await post(`/tally/setup/${ballotId}`);
  check("ballot created; 2-of-3 trustee key generated on-chain", created.ok && setup.ok && setup.qual?.length === 3, setup.error);
  const reg = await post("/sensors", device.publicKey);
  check("RA registers the capture device", reg.ok, reg.error);

  // Registration (client-side keys)
  const faceReadings = [unit(), unit(), unit()];
  const irisRead = irisReading();
  const voters = [];
  for (let i = 0; i < 3; i++) voters.push({ mode: "face", reading: faceReadings[i], ...(await registerVoter(`NID-F${i}`, "face", faceReadings[i])) });
  voters.push({ mode: "iris", reading: irisRead, ...(await registerVoter("NID-I0", "iris", irisRead)) });
  check("4 voters enrolled with client-generated commitments", voters.length === 4);

  const wrong = await client.openCredential(voters[0].sealed, "wrong password").then(() => false, () => true);
  check("credential file rejects a wrong password", wrong);

  // Votes: Alice, Bob, Alice (face) + Carol (iris)
  const plan = [[0, 0], [1, 1], [2, 0], [3, 2]];
  const nullifiers = [];
  for (const [vi, choice] of plan) {
    const v = voters[vi];
    const live = v.mode === "face" ? perturb(v.reading) : irisRecapture(v.reading);
    const r = await vote(v.sealed, v.mode, live, ballotId, choice).catch((e) => ({ ok: false, error: e.message }));
    check(`${v.mode} voter ${vi} votes ${OPTIONS[choice]} (attested capture)`, r.ok, r.error);
    if (r.nullifier) nullifiers.push(r.nullifier);
  }
  check("capture device never received a nullifier, key or credential",
    nullifiers.length === 4 && attestorSaw.every((s) => nullifiers.every((n) => !s.includes(n)) && !/"sk"|secretKey|commitment/.test(s)));

  const again = await vote(voters[0].sealed, "face", perturb(voters[0].reading), ballotId, 1).catch((e) => ({ ok: false, error: e.message }));
  check("double vote rejected", !again.ok && /Double/i.test(again.error || ""), again.error);

  const impostor = await vote(voters[1].sealed, "face", unit(), ballotId, 1).catch((e) => ({ ok: false, error: e.message }));
  check("impostor with a stolen credential file cannot produce a proof", !impostor.ok, (impostor.error || "").slice(0, 80));

  const tally = await post(`/tally/compute/${ballotId}`);
  const t = tally.tallies || {};
  check("tally = Alice 2, Bob 1, Carol 1 (accepted on-chain)", t.Alice === 2 && t.Bob === 1 && t.Carol === 1, JSON.stringify(t) + (tally.error || ""));

  const lateReading = unit();
  const lateVoter = await registerVoter("NID-F9", "face", lateReading);
  const late = await vote(lateVoter.sealed, "face", perturb(lateReading), ballotId, 0).catch((e) => ({ ok: false, error: e.message }));
  check("vote after the tally is rejected (ballot closed)", !late.ok && /not open/i.test(late.error || ""), late.error);

  // Universal verifiability: anyone re-checks totals from public data alone
  const verified = await post(`/tally/verify/${ballotId}`);
  check("published tally verifies (aggregates + partial decryption proofs)", verified.ok && verified.valid, JSON.stringify(verified.verifications?.map((v) => v.valid)));
  const bob = OPTIONS.indexOf("Bob");
  const forged = structuredClone(tally.tally);
  forged.options[bob].total += 5;
  const forgedRes = await post(`/tally/verify/${ballotId}`, forged);
  check("inflated total with the honest partial decryptions is rejected", forgedRes.ok && forgedRes.valid === false);
  const threshold = require(path.join(API, "crypto", "threshold"));
  const outsider = new threshold.Trustee(2);
  outsider.x = threshold.randScalar();
  const reproved = structuredClone(tally.tally);
  const chainBallot = await fabricClient.getBallot(ballotId);
  const votes = await fabricClient.getAllVotes(ballotId);
  const sums = threshold.aggregate(votes.map((v) => v.encryptedVote), chainBallot.numOptions);
  reproved.options[bob].partials[1] = outsider.partialDecrypt(ballotId, bob, threshold.tc.ser(sums[bob].c1));
  const reprovedRes = await post(`/tally/verify/${ballotId}`, reproved);
  check("partial decryption under a key outside the DKG is rejected", reprovedRes.ok && reprovedRes.valid === false);

  // ---------- what did the gateway see? ----------
  const voterBodies = seenBodies.filter((b) => !b.url.includes("/ballot/create") && !b.url.includes("/tally/"));
  const blob = voterBodies.map((b) => b.body).join("\n");
  const secrets = voters.flatMap((v) => [v.credential.sk, v.credential.salt]);
  const templateValues = voters.filter((v) => v.mode === "face").flatMap((v) => v.credential.template.filter((x) => Math.abs(Number(x)) > 100000).slice(0, 8));
  check("gateway never received a secret key or salt", secrets.every((s) => !blob.includes(s)));
  check("gateway never received a biometric template value", templateValues.every((s) => !blob.includes(`"${s}"`) && !blob.includes(`,${s},`)));
  check("gateway never received the password", !blob.includes(PASSWORD));
  const voteBodies = voterBodies.filter((b) => b.url.endsWith("/vote"));
  check("vote requests never contain a choice name", voteBodies.length > 0 && voteBodies.every((b) => OPTIONS.every((o) => !b.body.includes(`"${o}"`))));
  check("vote requests carry no NID or NID hash", voteBodies.every((b) => !/NID-|nidHash|nidNumber/.test(b.body)));
} finally {
  server.close();
}

console.log(`\n${failures} failure(s)`);
process.exit(failures ? 1 : 0);
