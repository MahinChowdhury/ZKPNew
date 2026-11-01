// ============================================================
// make_phone_bench.js — assemble a static page that proves the deployed
// face circuit (production wasm + zkey) in any browser, e.g. a phone.
//
//   node benchmark/phone/make_phone_bench.js [runs]
//   → benchmark/phone/www/ (index.html, snarkjs.min.js, face_auth.wasm,
//     face_auth.zkey, inputs.json); serve it and open it on the phone.
// ============================================================

const path = require("path");
const fs = require("fs");
const { voteInputs } = require("../bench_dim");

async function main() {
  const runs = Number(process.argv[2] || 5);
  const api = path.join(__dirname, "..", "..");
  const www = path.join(__dirname, "www");
  fs.mkdirSync(www, { recursive: true });

  fs.copyFileSync(path.join(__dirname, "index.html"), path.join(www, "index.html"));
  fs.copyFileSync(path.join(api, "node_modules", "snarkjs", "build", "snarkjs.min.js"), path.join(www, "snarkjs.min.js"));
  fs.copyFileSync(path.join(api, "circuits", "face_auth_js", "face_auth.wasm"), path.join(www, "face_auth.wasm"));
  fs.copyFileSync(path.join(api, "circuits", "face_auth.zkey"), path.join(www, "face_auth.zkey"));

  // One extra input for the warm-up run.
  const makeInput = await voteInputs(128);
  const inputs = [];
  for (let r = 0; r < runs + 1; r++) inputs.push(await makeInput());
  fs.writeFileSync(path.join(www, "inputs.json"), JSON.stringify(inputs));
  console.log(`wrote ${www} (${runs} timed runs + 1 warm-up)`);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
