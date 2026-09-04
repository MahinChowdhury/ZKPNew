const snark = require("./crypto/snark");
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");

const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function poseidonHashEmbeddingChunk8(embedding, salt) {
  const { poseidon, F } = await snark.initPoseidon();
  // 8 chunks of 8 elements
  const chunkHashes = [];
  for (let i = 0; i < 8; i++) {
    const chunk = embedding.slice(i * 8, (i + 1) * 8);
    const h = poseidon(chunk.map((v) => F.e(v)));
    chunkHashes.push(h);
  }
  const embeddingHash = poseidon(chunkHashes);
  const finalHash = poseidon([embeddingHash, F.e(salt)]);
  return F.toObject(finalHash);
}

async function testWitnessCalc() {
  const { poseidon, F } = await snark.initPoseidon();

  // Create registration data
  const floatEmb = new Array(64).fill(0).map(() => (Math.random() - 0.5) * 0.2);
  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";
  const salt = BigInt("0x" + saltHex);

  const regScaled = snark.scaleEmbedding(floatEmb);

  // Compute faceHash with chunkSize=8
  const faceHash = await poseidonHashEmbeddingChunk8(regScaled, salt);
  console.log("ChunkSize=8 faceHash: ", faceHash.toString());

  const commitments = [await snark.computeCommitment(faceHash, 99999n)];
  const { root, layers, zeroHashes } = await snark.buildMerkleTreeOptimized(commitments);
  const { pathElements, pathIndices } = snark.getMerkleProofOptimized(layers, zeroHashes, 0);
  const electionId = 12345n;
  const nullifier = await snark.computeNullifier(99999n, electionId);

  function toFS(val) {
    let v = BigInt(val);
    if (v < 0n) v = (v % BN128_PRIME) + BN128_PRIME;
    return (v % BN128_PRIME).toString();
  }

  const input = {
    faceHash: toFS(faceHash),
    merkleRoot: toFS(root),
    nullifier: toFS(nullifier),
    electionId: toFS(electionId),
    threshold_sq_num: "16",
    threshold_sq_den: "100",

    embedding: regScaled.map(toFS),
    registeredEmbedding: regScaled.map(toFS),
    salt: toFS(salt),
    secretKey: toFS(99999n),
    pathElements: pathElements.map(toFS),
    pathIndices: pathIndices.map(toFS),
  };

  const wasmPath = path.join(__dirname, "circuits", "face_auth_js", "face_auth.wasm");
  const wtnsPath = path.join(__dirname, "test.wtns");

  try {
    console.log("Calculating witness with WASM...");
    await snarkjs.wtns.calculate(input, wasmPath, wtnsPath);
    console.log("🎉🎉🎉 SUCCESS! WITNESS CALCULATED WITH ZERO ERRORS!");
  } catch (err) {
    console.error("❌ Failed!");
    console.error(err);
  } finally {
    if (fs.existsSync(wtnsPath)) fs.unlinkSync(wtnsPath);
  }
}

testWitnessCalc().catch(console.error);
