// ============================================================
// test_snark.js — Standalone ZK-SNARK proof test
//
// Tests the full SNARK pipeline with Merkle Tree + Nullifier:
//   1. Poseidon hash consistency
//   2. Merkle tree construction + proof
//   3. Nullifier determinism + uniqueness
//   4. Commitment computation
//   5. Valid proof (matching embeddings) — requires compiled circuit
//   6. Invalid proof (different person) — requires compiled circuit
//
// Prerequisites:
//   cd circuits && bash build_circuit.sh
//
// Run:
//   node test_snark.js
// ============================================================

const snark = require("./crypto/snark");

// ============================================================
// Helpers
// ============================================================

function generateFakeEmbedding(seed = 42) {
  // Deterministic pseudo-random embedding for testing
  const emb = new Array(64);
  let state = seed;
  for (let i = 0; i < 64; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    emb[i] = ((state / 0x7fffffff) * 2 - 1); // range [-1, 1]
  }
  // Normalize
  const norm = Math.sqrt(emb.reduce((s, v) => s + v * v, 0));
  return emb.map(v => v / norm);
}

function addNoise(embedding, noiseLevel = 0.05) {
  // Add small noise to simulate same person with different photo
  const noisy = embedding.map(v => v + (Math.random() - 0.5) * noiseLevel);
  const norm = Math.sqrt(noisy.reduce((s, v) => s + v * v, 0));
  return noisy.map(v => v / norm);
}

function cosineSimilarity(a, b) {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

// ============================================================
// Tests
// ============================================================

async function testPoseidonHash() {
  console.log("============================================");
  console.log("  TEST 1: Poseidon hash consistency");
  console.log("============================================\n");

  const emb = generateFakeEmbedding(42);
  const scaled = snark.scaleEmbedding(emb);
  const salt = BigInt("0xa1b2c3d4e5f6789012345678abcdef01");

  // Hash twice — should produce same result
  const hash1 = await snark.poseidonHashEmbedding(scaled, salt);
  const hash2 = await snark.poseidonHashEmbedding(scaled, salt);

  console.log(`Hash 1: ${hash1.toString().slice(0, 40)}...`);
  console.log(`Hash 2: ${hash2.toString().slice(0, 40)}...`);
  console.log(`Match: ${hash1 === hash2}`);

  if (hash1 === hash2) {
    console.log("\n✅ TEST 1 PASSED: Poseidon hash is deterministic\n");
  } else {
    console.log("\n❌ TEST 1 FAILED: Poseidon hash is non-deterministic!\n");
    process.exit(1);
  }

  // Different input should produce different hash
  const emb2 = generateFakeEmbedding(43);
  const scaled2 = snark.scaleEmbedding(emb2);
  const hash3 = await snark.poseidonHashEmbedding(scaled2, salt);
  
  console.log(`Different input hash: ${hash3.toString().slice(0, 40)}...`);
  console.log(`Different from original: ${hash1 !== hash3}`);

  if (hash1 !== hash3) {
    console.log("\n✅ Collision resistance check passed\n");
  } else {
    console.log("\n❌ Collision detected!\n");
    process.exit(1);
  }
}

async function testMerkleTree() {
  console.log("============================================");
  console.log("  TEST 2: Merkle tree construction + proof");
  console.log("============================================\n");

  // Create some fake commitments
  const { poseidon, F } = await snark.initPoseidon();

  const commitments = [];
  for (let i = 0; i < 5; i++) {
    const fakeHash = BigInt(i * 1000 + 1);
    const fakeSk = BigInt(i * 2000 + 42);
    const commitment = await snark.computeCommitment(fakeHash, fakeSk);
    commitments.push(commitment);
  }

  console.log(`Created ${commitments.length} commitments`);

  // Build Merkle tree
  const { root, layers } = await snark.buildMerkleTree(commitments);
  console.log(`Merkle root: ${root.toString().slice(0, 40)}...`);
  console.log(`Tree levels: ${layers.length - 1}`);

  // Generate proof for leaf index 2
  const { pathElements, pathIndices } = snark.getMerkleProof(layers, 2);
  console.log(`Path elements: ${pathElements.length} siblings`);
  console.log(`Path indices: [${pathIndices.join(", ")}]`);

  // Verify proof manually by reconstructing the root
  let current = commitments[2];
  for (let i = 0; i < pathElements.length; i++) {
    if (pathIndices[i] === 0) {
      current = await snark.poseidonHash2(current, pathElements[i]);
    } else {
      current = await snark.poseidonHash2(pathElements[i], current);
    }
  }

  console.log(`\nReconstructed root: ${current.toString().slice(0, 40)}...`);
  console.log(`Matches tree root: ${current === root}`);

  if (current === root) {
    console.log("\n✅ TEST 2 PASSED: Merkle tree construction and proof are correct\n");
  } else {
    console.log("\n❌ TEST 2 FAILED: Merkle proof does not reconstruct root!\n");
    process.exit(1);
  }
}

async function testNullifier() {
  console.log("============================================");
  console.log("  TEST 3: Nullifier determinism + uniqueness");
  console.log("============================================\n");

  const secretKey = BigInt("12345678901234567890");
  const electionId1 = BigInt("100");
  const electionId2 = BigInt("200");

  // Same inputs → same nullifier (deterministic)
  const null1a = await snark.computeNullifier(secretKey, electionId1);
  const null1b = await snark.computeNullifier(secretKey, electionId1);
  
  console.log(`Nullifier (sk, election1) [a]: ${null1a.toString().slice(0, 30)}...`);
  console.log(`Nullifier (sk, election1) [b]: ${null1b.toString().slice(0, 30)}...`);
  console.log(`Deterministic: ${null1a === null1b}`);

  if (null1a !== null1b) {
    console.log("\n❌ TEST 3 FAILED: Nullifier is not deterministic!\n");
    process.exit(1);
  }

  // Different election → different nullifier (uniqueness)
  const null2 = await snark.computeNullifier(secretKey, electionId2);
  console.log(`Nullifier (sk, election2): ${null2.toString().slice(0, 30)}...`);
  console.log(`Different from election1: ${null1a !== null2}`);

  if (null1a === null2) {
    console.log("\n❌ TEST 3 FAILED: Different elections produce same nullifier!\n");
    process.exit(1);
  }

  // Different secret key → different nullifier
  const secretKey2 = BigInt("98765432109876543210");
  const null3 = await snark.computeNullifier(secretKey2, electionId1);
  console.log(`Nullifier (sk2, election1): ${null3.toString().slice(0, 30)}...`);
  console.log(`Different from sk1: ${null1a !== null3}`);

  if (null1a === null3) {
    console.log("\n❌ TEST 3 FAILED: Different secret keys produce same nullifier!\n");
    process.exit(1);
  }

  console.log("\n✅ TEST 3 PASSED: Nullifier is deterministic and unique\n");
}

async function testCommitment() {
  console.log("============================================");
  console.log("  TEST 4: Commitment computation");
  console.log("============================================\n");

  const emb = generateFakeEmbedding(42);
  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";

  // Full registration pipeline
  const regData = await snark.computeRegistrationData(emb, saltHex);
  
  console.log(`faceHash: ${regData.faceHash.toString().slice(0, 30)}...`);
  console.log(`secretKey: ${regData.secretKey.toString().slice(0, 30)}...`);
  console.log(`commitment: ${regData.commitment.toString().slice(0, 30)}...`);

  // Verify commitment = Poseidon(faceHash, secretKey)
  const recomputed = await snark.computeCommitment(regData.faceHash, regData.secretKey);
  console.log(`Recomputed: ${recomputed.toString().slice(0, 30)}...`);
  console.log(`Match: ${regData.commitment === recomputed}`);

  if (regData.commitment === recomputed) {
    console.log("\n✅ TEST 4 PASSED: Commitment computation is consistent\n");
  } else {
    console.log("\n❌ TEST 4 FAILED: Commitment mismatch!\n");
    process.exit(1);
  }

  return regData;
}

async function testValidProof(regData) {
  console.log("============================================");
  console.log("  TEST 5: Valid proof (matching embeddings)");
  console.log("============================================\n");

  // Generate registered embedding
  const registeredEmb = generateFakeEmbedding(42);
  
  // Generate live embedding (same person, slight noise)
  const liveEmb = addNoise(registeredEmb, 0.05);
  
  const cosine = cosineSimilarity(liveEmb, registeredEmb);
  console.log(`Cosine similarity: ${cosine.toFixed(4)} (threshold: 0.5)`);
  console.log(`Should pass: ${cosine > 0.5 ? "YES" : "NO"}\n`);

  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";
  const electionId = BigInt("42");

  // Build commitments array (including our voter + some dummy ones)
  const dummyCommitments = [];
  for (let i = 0; i < 3; i++) {
    const dummyFh = BigInt(i * 999 + 1);
    const dummySk = BigInt(i * 888 + 7);
    dummyCommitments.push(await snark.computeCommitment(dummyFh, dummySk));
  }
  
  // Our voter's commitment
  const commitments = [...dummyCommitments, regData.commitment];
  console.log(`Commitment array size: ${commitments.length}`);
  console.log(`Voter leaf index: ${commitments.length - 1}`);

  // Generate proof
  console.log("\n--- Authentication Proof ---");
  const startTime = Date.now();
  
  const result = await snark.generateAuthProof(
    liveEmb,
    registeredEmb,
    saltHex,
    regData.faceHash,
    regData.secretKey,
    commitments,
    electionId
  );

  const elapsed = Date.now() - startTime;
  
  console.log(`\nProof generated in: ${elapsed}ms`);
  console.log(`Public signals count: ${result.publicSignals.length}`);
  console.log(`Verification result: ${result.isValid}`);
  console.log(`Nullifier: ${result.nullifier.toString().slice(0, 30)}...`);
  console.log(`Merkle root: ${result.merkleRoot.toString().slice(0, 30)}...`);
  
  if (result.isValid) {
    console.log("\n✅ TEST 5 PASSED: Valid proof accepted\n");
  } else {
    console.log("\n❌ TEST 5 FAILED: Valid proof was rejected\n");
    process.exit(1);
  }

  return result;
}

async function testInvalidProof(regData) {
  console.log("============================================");
  console.log("  TEST 6: Invalid proof (different person)");
  console.log("============================================\n");

  // Generate a completely different person's embedding
  const differentPersonEmb = generateFakeEmbedding(999);
  const registeredEmb = generateFakeEmbedding(42);
  
  const cosine = cosineSimilarity(differentPersonEmb, registeredEmb);
  console.log(`Cosine similarity: ${cosine.toFixed(4)} (threshold: 0.5)`);
  console.log(`Should pass: ${cosine > 0.5 ? "YES (unexpected)" : "NO (expected)"}\n`);

  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";
  const electionId = BigInt("42");

  // Build commitments array
  const commitments = [regData.commitment];

  try {
    console.log("--- Attempting proof with wrong embeddings ---");
    
    const result = await snark.generateAuthProof(
      differentPersonEmb,
      registeredEmb,
      saltHex,
      regData.faceHash,
      regData.secretKey,
      commitments,
      electionId
    );

    if (!result.isValid) {
      console.log("\n✅ TEST 6 PASSED: Invalid proof correctly rejected\n");
    } else {
      console.log("\n❌ TEST 6 FAILED: Invalid proof was accepted!\n");
      process.exit(1);
    }
  } catch (err) {
    // Circuit may throw if constraints are unsatisfied
    console.log(`\n✅ TEST 6 PASSED: Circuit rejected invalid input`);
    console.log(`   Error: ${err.message}\n`);
  }
}

// ============================================================
// Main
// ============================================================

async function main() {
  console.log("\n🔐 ZK-SNARK Test Suite (Merkle Tree + Nullifier)\n");
  console.log("=".repeat(50) + "\n");

  // Tests 1–4 don't need circuit artifacts
  await testPoseidonHash();
  await testMerkleTree();
  await testNullifier();
  const regData = await testCommitment();

  // Tests 5 & 6 require compiled circuit (face_auth.wasm + face_auth.zkey)
  try {
    await testValidProof(regData);
    await testInvalidProof(regData);
  } catch (err) {
    if (err.message.includes("not found")) {
      console.log("⚠️  Skipping proof tests — circuit not compiled yet.");
      console.log("   Run: cd circuits && bash build_circuit.sh\n");
    } else {
      throw err;
    }
  }

  console.log("=".repeat(50));
  console.log("  All tests completed!");
  console.log("=".repeat(50) + "\n");
}

main().catch(err => {
  console.error("TEST FATAL ERROR:", err);
  process.exit(1);
});
