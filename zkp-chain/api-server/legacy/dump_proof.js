const fs = require('fs');
const snarkjs = require('snarkjs');
const path = require('path');
const { getFaceEmbedding } = require('./crypto/embedding.js');
const snark = require('./crypto/snark.js');

async function run() {
  const embedding = await getFaceEmbedding('/mnt/c/Development/ZKPNew/zkp-chain/api-server/photo12.jpg');
  const saltHex = '1234567890abcdef1234567890abcdef';
  const regData = await snark.computeRegistrationData(embedding, saltHex);
  const commitments = [regData.commitment];
  const { proof, publicSignals } = await snark.generateAuthProof(
    embedding,
    embedding,
    saltHex,
    regData.faceHash,
    regData.secretKey,
    commitments,
    0n
  );
  fs.writeFileSync('proof.json', JSON.stringify(proof, null, 2));
  fs.writeFileSync('public.json', JSON.stringify(publicSignals, null, 2));
  console.log('Proof dumped!');
}
run().catch(console.error);
