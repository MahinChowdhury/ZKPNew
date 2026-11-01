// ============================================================
// bench_dim.js — proving cost of the face circuit at template dimension d
// (the WASM prover the browser client uses). Run by bench_dim.sh, which
// compiles FaceAuth(d, ...) and its keys into benchmark/build_dim/d<d>/.
//
//   node benchmark/bench_dim.js <d> <runs>   → one JSON line on stdout
// ============================================================

const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const h = require("../attacks/soundness/harness");
const { loadSigner } = require("../sensor/attest-core");

// Returns makeInput(): a fresh valid witness input for FaceAuth(d, ...) on each
// call (one enrolled voter, a new noisy live sample and device signature).
async function voteInputs(d) {
  const crypto = require("crypto");
  const template = h.randomUnitEmbedding(d);
  const salt = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
  const sk = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
  const faceHash = await h.H(await h.faceDigestOf(template), salt);
  const commitment = await h.H(faceHash, sk);
  const tree = await h.buildTree([commitment]);
  const mp = await h.merklePath(tree, 0);

  const signer = await loadSigner();
  const sensorTree = await h.buildTree([await h.H(signer.publicKey.ax, signer.publicKey.ay)], h.SENSOR_LEVELS);
  const sp = await h.merklePath(sensorTree, 0);

  const electionId = h.electionIdFor("bench-dim");
  const nullifier = await h.H(sk, electionId);

  return async function makeInput() {
    const live = h.noisyCopy(template);
    const nonce = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
    const sig = signer.sign(await h.H(await h.faceDigestOf(live), electionId, await h.H(nullifier, nonce)));
    return {
      merkleRoot: h.fieldStr(tree.root), nullifier: h.fieldStr(nullifier),
      electionId: h.fieldStr(electionId), voteBinding: "12345", sensorRoot: h.fieldStr(sensorTree.root),
      embedding: live.map(h.fieldStr), registeredEmbedding: template.map(h.fieldStr),
      salt: h.fieldStr(salt), secretKey: h.fieldStr(sk),
      pathElements: mp.pathElements.map(h.fieldStr), pathIndices: mp.pathIndices.map(h.fieldStr),
      sessionNonce: h.fieldStr(nonce), sensorAx: signer.publicKey.ax, sensorAy: signer.publicKey.ay,
      sigR8x: sig.R8x, sigR8y: sig.R8y, sigS: sig.S,
      sensorPathElements: sp.pathElements.map(h.fieldStr), sensorPathIndices: sp.pathIndices.map(h.fieldStr),
    };
  };
}

async function main() {
  const d = Number(process.argv[2]);
  const runs = Number(process.argv[3] || 10);
  const dir = path.join(__dirname, "build_dim", `d${d}`);
  const wasm = path.join(dir, "face_auth_js", "face_auth.wasm");
  const zkey = path.join(dir, "face_auth.zkey");
  const vkey = JSON.parse(fs.readFileSync(path.join(dir, "vkey.json")));
  const makeInput = await voteInputs(d);

  const times = [];
  for (let r = 0; r < runs + 1; r++) {          // run 0 is a warm-up and is discarded
    const input = await makeInput();
    const t0 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
    const ms = performance.now() - t0;
    if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) throw new Error("proof failed to verify");
    if (r > 0) times.push(ms);
  }

  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const sd = Math.sqrt(times.reduce((a, b) => a + (b - mean) ** 2, 0) / (times.length - 1));
  const info = await snarkjs.r1cs.info(path.join(dir, "face_auth.r1cs"));
  console.log(JSON.stringify({
    dim: d, runs, constraints: info.nConstraints,
    prove_ms_mean: mean, prove_ms_ci95: 1.96 * sd / Math.sqrt(times.length),
    zkey_bytes: fs.statSync(zkey).size,
    peak_rss_bytes: process.resourceUsage().maxRSS * 1024,
  }));
  process.exit(0);   // snarkjs leaves worker threads alive
}

module.exports = { voteInputs };
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
