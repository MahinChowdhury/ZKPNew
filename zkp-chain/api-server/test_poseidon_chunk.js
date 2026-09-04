const circomlibjs = require("circomlibjs");

const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toField(val) {
  let v = BigInt(val);
  if (v < 0n) v = (v % BN128_PRIME) + BN128_PRIME;
  return v % BN128_PRIME;
}

async function testChunk() {
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  // 16 scaled integers (some positive, some negative)
  const rawChunk = [
    -83835n, 120450n, -4500n, 0n, -129999n, 88888n, -1n, 200000n,
    -50000n, 7777n, -8888n, 99999n, -123456n, 654321n, -999n, 1234n
  ];

  // Method 1: passing raw BigInts to F.e
  const h1 = poseidon(rawChunk.map(v => F.e(v)));

  // Method 2: mapping to positive field elements first
  const fieldChunk = rawChunk.map(toField);
  const h2 = poseidon(fieldChunk.map(v => F.e(v)));

  console.log("h1:", F.toString(h1));
  console.log("h2:", F.toString(h2));
  console.log("Equal:", F.eq(h1, h2));
}

testChunk().catch(console.error);
