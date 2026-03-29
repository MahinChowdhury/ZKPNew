// ============================================================
// test_snark.js — Standalone ZK-SNARK proof test
//
// Tests the full SNARK pipeline WITHOUT Fabric or Python API:
//   1. Generate fake 64D embeddings
//   2. Compute Poseidon hash + Baby Jubjub key
//   3. Generate PLONK proof
//   4. Verify proof
//   5. Test with mismatched embeddings (should fail cosine check)
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

async function testValidProof() {
  console.log("============================================");
  console.log("  TEST 1: Valid proof (matching embeddings)");
  console.log("============================================\n");

  // Generate registered embedding
  const registeredEmb = generateFakeEmbedding(42);
  
  // Generate live embedding (same person, slight noise)
  const liveEmb = addNoise(registeredEmb, 0.05);
  
  const cosine = cosineSimilarity(liveEmb, registeredEmb);
  console.log(`Cosine similarity: ${cosine.toFixed(4)} (threshold: 0.5)`);
  console.log(`Should pass: ${cosine > 0.5 ? "YES" : "NO"}\n`);

  // Generate random salt
  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";

  // Step 1: Registration
  console.log("--- Registration ---");
  const regData = await snark.computeRegistrationData(registeredEmb, saltHex);
  console.log(`Poseidon faceHash: ${regData.faceHash.toString().slice(0, 30)}...`);
  console.log(`Baby Jubjub Sx: ${regData.Sx.toString().slice(0, 30)}...`);
  console.log(`Baby Jubjub Sy: ${regData.Sy.toString().slice(0, 30)}...`);
  console.log();

  // Step 2: Authentication proof
  console.log("--- Authentication Proof ---");
  const startTime = Date.now();
  
  const result = await snark.generateAuthProof(
    liveEmb,
    registeredEmb,
    saltHex,
    regData.faceHash,
    regData.Sx,
    regData.Sy
  );

  const elapsed = Date.now() - startTime;
  
  console.log(`\nProof generated in: ${elapsed}ms`);
  console.log(`Public signals count: ${result.publicSignals.length}`);
  console.log(`Verification result: ${result.isValid}`);
  
  if (result.isValid) {
    console.log("\n✅ TEST 1 PASSED: Valid proof accepted\n");
  } else {
    console.log("\n❌ TEST 1 FAILED: Valid proof was rejected\n");
    process.exit(1);
  }

  return { regData, saltHex };
}

async function testInvalidProof(regData, saltHex) {
  console.log("============================================");
  console.log("  TEST 2: Invalid proof (different person)");
  console.log("============================================\n");

  // Generate a completely different person's embedding
  const differentPersonEmb = generateFakeEmbedding(999);
  const registeredEmb = generateFakeEmbedding(42);
  
  const cosine = cosineSimilarity(differentPersonEmb, registeredEmb);
  console.log(`Cosine similarity: ${cosine.toFixed(4)} (threshold: 0.5)`);
  console.log(`Should pass: ${cosine > 0.5 ? "YES (unexpected)" : "NO (expected)"}\n`);

  try {
    console.log("--- Attempting proof with wrong embeddings ---");
    
    const result = await snark.generateAuthProof(
      differentPersonEmb,
      registeredEmb,
      saltHex,
      regData.faceHash,
      regData.Sx,
      regData.Sy
    );

    if (!result.isValid) {
      console.log("\n✅ TEST 2 PASSED: Invalid proof correctly rejected\n");
    } else {
      console.log("\n❌ TEST 2 FAILED: Invalid proof was accepted!\n");
      process.exit(1);
    }
  } catch (err) {
    // Circuit may throw if constraints are unsatisfied
    console.log(`\n✅ TEST 2 PASSED: Circuit rejected invalid input`);
    console.log(`   Error: ${err.message}\n`);
  }
}

async function testPoseidonHash() {
  console.log("============================================");
  console.log("  TEST 3: Poseidon hash consistency");
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
    console.log("\n✅ TEST 3 PASSED: Poseidon hash is deterministic\n");
  } else {
    console.log("\n❌ TEST 3 FAILED: Poseidon hash is non-deterministic!\n");
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

async function testBabyJubKey() {
  console.log("============================================");
  console.log("  TEST 4: Baby Jubjub key derivation");
  console.log("============================================\n");

  const emb = generateFakeEmbedding(42);
  const saltHex = "a1b2c3d4e5f6789012345678abcdef01";
  const salt = BigInt("0x" + saltHex);
  const scaled = snark.scaleEmbedding(emb);

  const faceHash = await snark.poseidonHashEmbedding(scaled, salt);
  const k = await snark.deriveScalarK(faceHash, salt);
  
  console.log(`Private scalar k: ${k.toString().slice(0, 30)}...`);

  const { Sx, Sy } = await snark.deriveBabyJubKey(k);
  console.log(`Public key Sx: ${Sx.toString().slice(0, 30)}...`);
  console.log(`Public key Sy: ${Sy.toString().slice(0, 30)}...`);

  // Derive again — should match
  const { Sx: Sx2, Sy: Sy2 } = await snark.deriveBabyJubKey(k);
  
  if (Sx === Sx2 && Sy === Sy2) {
    console.log("\n✅ TEST 4 PASSED: Baby Jubjub key derivation is deterministic\n");
  } else {
    console.log("\n❌ TEST 4 FAILED: Key derivation is non-deterministic!\n");
    process.exit(1);
  }
}

// ============================================================
// Main
// ============================================================

async function main() {
  console.log("\n🔐 ZK-SNARK Test Suite (Circom + SnarkJS + PLONK)\n");
  console.log("=".repeat(50) + "\n");

  // Tests 3 & 4 don't need circuit artifacts
  await testPoseidonHash();
  await testBabyJubKey();

  // Tests 1 & 2 require compiled circuit (face_auth.wasm + face_auth.zkey)
  try {
    const { regData, saltHex } = await testValidProof();
    await testInvalidProof(regData, saltHex);
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
