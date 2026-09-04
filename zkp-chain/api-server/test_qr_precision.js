const snark = require("./crypto/snark");

async function testQRFloatPrecision() {
  await snark.initPoseidon();
  
  // Simulate face embedding floats from DeepFace / PCA
  const floatEmb = new Array(64).fill(0).map(() => (Math.random() - 0.5) * 0.2);
  const salt = "a1b2c3d4e5f6789012345678abcdef01";

  // 1. Registration scaling & hashing
  const scaledReg = snark.scaleEmbedding(floatEmb);
  const hashReg = await snark.poseidonHashEmbedding(scaledReg, BigInt("0x" + salt));

  // 2. Simulate QR payload JSON stringify -> decrypt -> JSON parse
  const qrPayload = { faceEmbedding: floatEmb };
  const jsonStr = JSON.stringify(qrPayload);
  const decryptedData = JSON.parse(jsonStr);

  // 3. Voting scaling & hashing from decrypted QR float embedding
  const floatEmbFromQR = decryptedData.faceEmbedding;
  const scaledVote = snark.scaleEmbedding(floatEmbFromQR);
  const hashVote = await snark.poseidonHashEmbedding(scaledVote, BigInt("0x" + salt));

  console.log("Original float [0]:", floatEmb[0]);
  console.log("QR float [0]:      ", floatEmbFromQR[0]);
  console.log("Scaled Reg [0]:   ", scaledReg[0].toString());
  console.log("Scaled Vote [0]:  ", scaledVote[0].toString());
  console.log("Hash Reg:         ", hashReg.toString());
  console.log("Hash Vote:        ", hashVote.toString());
  console.log("Hashes match:     ", hashReg === hashVote);
}

testQRFloatPrecision().catch(console.error);
