const circomlibjs = require("circomlibjs");

async function testLimits() {
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  const arr16 = new Array(16).fill(1n);
  try {
    const h16 = poseidon(arr16.map(v => F.e(v)));
    console.log("Poseidon(16) output:", F.toObject(h16).toString());
  } catch (err) {
    console.error("Poseidon(16) ERROR:", err.message);
  }

  const arr8 = new Array(8).fill(1n);
  try {
    const h8 = poseidon(arr8.map(v => F.e(v)));
    console.log("Poseidon(8) output: ", F.toObject(h8).toString());
  } catch (err) {
    console.error("Poseidon(8) ERROR:", err.message);
  }
}

testLimits().catch(console.error);
