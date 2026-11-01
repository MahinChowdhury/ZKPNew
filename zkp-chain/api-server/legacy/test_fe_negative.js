const circomlibjs = require("circomlibjs");

async function testFeNegative() {
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;
  const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  const val = -83835n;
  const valField = (val % BN128_PRIME) + BN128_PRIME;

  const e1 = F.e(val);
  const e2 = F.e(valField);

  console.log("F.e(-83835n):            ", F.toString(e1));
  console.log("F.e(BN128_PRIME-83835n): ", F.toString(e2));
  console.log("Are F.e outputs equal?   ", F.eq(e1, e2));

  const h1 = poseidon([e1]);
  const h2 = poseidon([e2]);
  console.log("Poseidon hash 1:", F.toObject(h1).toString());
  console.log("Poseidon hash 2:", F.toObject(h2).toString());
  console.log("Poseidon equal? ", F.eq(h1, h2));
}

testFeNegative().catch(console.error);
