// ============================================================
// test_snark.mjs — smoke test of the deployed proving stack
//
// Uses the production circuits (circuits/*.wasm, *.zkey, verification
// keys), the voter client's own code (frontend/src/crypto/voterClient.js),
// the capture-device attestor and the real chaincode on an in-memory
// Fabric stub. Replaces the pre-revision test_snark.js / dump_proof.js,
// which drove the retired server-side prover (see legacy/README.md).
//
// Checks:
//   1. the three JS mirrors of the face template hash agree
//      (voter client, legacy crypto/snark.js, attack harness)
//   2. a genuine face vote proves, verifies and is accepted by castVote
//   3. an impostor's face cannot produce a proof
//   4. an out-of-range coordinate is refused by the client
//   5. a second vote by the same credential is rejected
//   6. a genuine iris vote proves and verifies
//
// Run (from api-server/, after circuits/build_*.sh):
//   node test_snark.mjs           # tests
//   node test_snark.mjs --dump    # also write proof.json / public.json
// ============================================================

import { createRequire } from "module";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const API = path.dirname(fileURLToPath(import.meta.url));
const snarkjs = require("snarkjs");
const h = require(path.join(API, "attacks", "soundness", "harness"));
const legacySnark = require(path.join(API, "crypto", "snark"));
const crypto = require("crypto");
const { loadSigner, attest, attestEnrollment } = require(path.join(API, "sensor", "attest-core"));
const client = await import(path.join(API, "..", "frontend", "src", "crypto", "voterClient.js"));

const CIRC = path.join(API, "circuits");
const ARTIFACTS = {
  face: { wasm: path.join(CIRC, "face_auth_js", "face_auth.wasm"), zkey: path.join(CIRC, "face_auth.zkey") },
  iris: { wasm: path.join(CIRC, "iris_auth_js", "iris_auth.wasm"), zkey: path.join(CIRC, "iris_auth.zkey") },
  enroll: { wasm: path.join(CIRC, "enroll_auth_js", "enroll_auth.wasm"), zkey: path.join(CIRC, "enroll_auth.zkey") },
};
const VKEY = {
  face: JSON.parse(fs.readFileSync(path.join(CIRC, "verification_key.json"))),
  iris: JSON.parse(fs.readFileSync(path.join(CIRC, "iris_verification_key.json"))),
};

const unit = (d = 128) => { const v = Array.from({ length: d }, () => Math.random() * 2 - 1); const k = Math.hypot(...v); return v.map((x) => x / k); };
const perturb = (v, s = 0.05) => { const w = v.map((x) => x + s * (Math.random() * 2 - 1)); const k = Math.hypot(...w); return w.map((x) => x / k); };
const irisReading = () => ({ irisCode: Array.from({ length: 4096 }, () => (Math.random() < 0.5 ? 1 : 0)), noiseMask: Array(4096).fill(1) });
const irisRecapture = (r) => ({ irisCode: r.irisCode.map((b) => (Math.random() < 0.06 ? b ^ 1 : b)), noiseMask: r.noiseMask });

let failures = 0;
async function check(name, fn) {
  try {
    const detail = await fn();
    console.log(`PASS  ${name}${detail ? ` — ${detail}` : ""}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name} — ${e.message.split("\n")[0]}`);
  }
}
async function rejects(fn, what) {
  try { await fn(); } catch (e) { return e.message.split("\n")[0].slice(0, 90); }
  throw new Error(`${what} was accepted`);
}

// One ledger: the real chaincode, one registered capture device, a 2-of-3 ballot
const IdentityContract = require(path.join(API, "..", "chaincode", "identity", "lib", "identityContract.js"));
const contract = new IdentityContract();
const { ctx } = h.makeLedger();
const device = await loadSigner();
await h.quiet(() => contract.registerSensor(ctx, device.publicKey.ax, device.publicKey.ay));
const { record: ballot } = await h.setupBallot(contract, ctx, "test-snark", 3);

async function enroll(mode, reading, nid) {
  if (mode === "iris") {
    const credential = await client.createCredential(mode, client.toTemplate(mode, reading));
    await h.quiet(() => contract.registerIris(ctx, nid, credential.commitment));
    return credential;
  }
  // Face: kiosk-attested enrollment (enroll_auth.circom)
  const nidHash = crypto.createHash("sha256").update(nid).digest("hex");
  const attestation = await attestEnrollment(device, { mode, reading, nidHash });
  const credential = await client.createCredential(mode, attestation.template);
  const sensors = JSON.parse(await h.quiet(() => contract.getSensors(ctx)));
  const { proof, publicSignals } = await client.proveEnrollment({ credential, attestation, sensors, nidHash, artifacts: ARTIFACTS.enroll });
  await h.quiet(() => contract.register(ctx, nidHash, credential.commitment, JSON.stringify(proof), JSON.stringify(publicSignals)));
  return credential;
}

async function buildVote(mode, credential, live) {
  const session = await client.startVoteSession(credential, ballot);
  const attestation = await attest(device, { mode, reading: live, electionId: session.electionId, sessionCommit: session.sessionCommit });
  const commitments = JSON.parse(await h.quiet(() => contract[mode === "face" ? "getCommitments" : "getIrisCommitments"](ctx)));
  const sensors = JSON.parse(await h.quiet(() => contract.getSensors(ctx)));
  return client.prepareVote({ credential, session, attestation, sensors, ballot, choiceIndex: 0, commitments, artifacts: ARTIFACTS[mode] });
}

const castVote = (mode, tx) => h.quiet(() => contract.castVote(ctx, JSON.stringify(tx.proof), JSON.stringify(tx.publicSignals),
  tx.nullifier, JSON.stringify(tx.encryptedBallot), tx.ballotId, mode));

const faceReading = unit();
const face = await enroll("face", faceReading, "nid-test-face");
let genuine;

await check("face template hash: voter client = crypto/snark.js = attack harness", async () => {
  const salt = BigInt(face.salt);
  const viaClient = await h.H(await client.templateDigest("face", face.template.map(BigInt)), salt);
  const viaLegacy = await legacySnark.poseidonHashEmbedding(face.template.map(BigInt), salt);
  const viaHarness = await h.H(await h.faceDigestOf(face.template.map(BigInt)), salt);
  if (viaClient !== viaLegacy || viaClient !== viaHarness) throw new Error("digests differ");
  return `${String(viaClient).slice(0, 12)}…`;
});

await check("genuine face vote proves, verifies and is accepted on-chain", async () => {
  genuine = await buildVote("face", face, perturb(faceReading));
  if (!(await snarkjs.groth16.verify(VKEY.face, genuine.publicSignals, genuine.proof))) throw new Error("proof does not verify");
  const r = JSON.parse(await castVote("face", genuine));
  return `stored as ${r.voteId ?? "vote"}`;
});

await check("impostor face cannot produce a proof", async () =>
  rejects(() => buildVote("face", face, unit()), "impostor proof"));

await check("out-of-range coordinate is refused by the client", async () =>
  rejects(() => client.templateDigest("face", face.template.map((x, i) => (i ? BigInt(x) : 1n << 19n))), "coordinate 2^19"));

await check("second vote by the same credential is rejected", async () =>
  rejects(async () => castVote("face", await buildVote("face", face, perturb(faceReading))), "double vote"));

await check("genuine iris vote proves and verifies", async () => {
  const reading = irisReading();
  const iris = await enroll("iris", reading, "nid-test-iris");
  const tx = await buildVote("iris", iris, irisRecapture(reading));
  if (!(await snarkjs.groth16.verify(VKEY.iris, tx.publicSignals, tx.proof))) throw new Error("proof does not verify");
});

if (process.argv.includes("--dump") && genuine) {
  fs.writeFileSync(path.join(API, "proof.json"), JSON.stringify(genuine.proof, null, 2));
  fs.writeFileSync(path.join(API, "public.json"), JSON.stringify(genuine.publicSignals, null, 2));
  console.log("wrote proof.json, public.json");
}
console.log(`\n${failures} failure(s)`);
process.exit(failures ? 1 : 0);
