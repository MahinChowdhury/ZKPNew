/**
 * ═══════════════════════════════════════════════════════════════════
 *  Category 4 — Vote Manipulation & ZKP Bypass Attacks
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Tests the system's resistance to vote manipulation via
 *  ZKP forgery and ElGamal ciphertext malleability.
 *  OFFLINE crypto tests — no live network needed.
 *
 *  Tests:
 *    4.1  Invalid vote value injection (m ∉ {0,1})
 *    4.2  ZKP proof component tampering (all 8 fields)
 *    4.3  Ciphertext malleability attack
 *    4.4  ZKP cross-vote proof reuse
 *    4.5  Forged proof from scratch (random components)
 *
 *  Run: node attacks/04_zkp_attack_test.js
 */

"use strict";

const {
  ec, BN, crypto,
  nowMs, suppress,
  printHeader, printSubHeader, printResult, printTable,
  saveResults
} = require("./utils");
const homomorphic = require("../crypto/homomorphic");

async function run() {
  printHeader("Category 4 — Vote Manipulation & ZKP Bypass Attacks");

  const results = {
    category: "Vote Manipulation & ZKP Bypass",
    timestamp: new Date().toISOString(),
    tests: {}
  };

  // Setup: generate keypair and valid vote
  const kp = suppress(() => homomorphic.generateKeypair());
  const validVote0 = suppress(() => homomorphic.encrypt(kp.publicKey, 0));
  const validVote1 = suppress(() => homomorphic.encrypt(kp.publicKey, 1));
  const validProof0 = suppress(() => homomorphic.proveValidVote(kp.publicKey, validVote0, 0, validVote0.r));
  const validProof1 = suppress(() => homomorphic.proveValidVote(kp.publicKey, validVote1, 1, validVote1.r));

  // Sanity checks
  const sanity0 = suppress(() => homomorphic.verifyValidVote(kp.publicKey, validVote0, validProof0));
  const sanity1 = suppress(() => homomorphic.verifyValidVote(kp.publicKey, validVote1, validProof1));
  printResult("Sanity: valid proof for m=0 verifies", sanity0, sanity0);
  printResult("Sanity: valid proof for m=1 verifies", sanity1, sanity1);

  // ─── 4.1  Invalid Vote Value Injection ──────────────────────────
  printSubHeader("4.1  Invalid Vote Value Injection");

  const invalidValues = [2, 3, 5, 10, 100, -1, 1000];
  const invalidValueResults = [];

  for (const m of invalidValues) {
    let blocked = false;
    try {
      suppress(() => {
        const cipher = homomorphic.encrypt(kp.publicKey, m);
        homomorphic.proveValidVote(kp.publicKey, cipher, m, cipher.r);
      });
    } catch (err) {
      blocked = true;
    }
    invalidValueResults.push({ value: m, blocked });
    printResult(`m=${m} → proof generation blocked`, blocked, blocked);
  }

  const allInvalidBlocked = invalidValueResults.every(r => r.blocked);
  results.tests["4.1_invalid_vote_values"] = {
    values_tested: invalidValues,
    all_blocked: allInvalidBlocked,
    details: invalidValueResults,
    pass: allInvalidBlocked
  };

  // ─── 4.2  ZKP Proof Component Tampering ─────────────────────────
  printSubHeader("4.2  ZKP Proof Component Tampering (all 8 fields)");

  const proofFields = ["a1", "b1", "a2", "b2", "d1", "d2", "r1", "r2"];
  const tamperResults = [];

  for (const field of proofFields) {
    const tampered = JSON.parse(JSON.stringify(validProof1));
    let rejected = false;

    try {
      if (field === "d1" || field === "d2" || field === "r1" || field === "r2") {
        // Scalar fields — add 1
        const val = new BN(tampered[field], 16);
        tampered[field] = val.addn(1).umod(ec.curve.n).toString(16);
      } else {
        // Point fields — multiply x by 2 (creates invalid proof relationship)
        const xVal = new BN(tampered[field].x, 16);
        // Generate a different random point
        const rndPt = ec.genKeyPair().getPublic();
        tampered[field] = {
          x: rndPt.getX().toString(16),
          y: rndPt.getY().toString(16)
        };
      }

      const verified = suppress(() =>
        homomorphic.verifyValidVote(kp.publicKey, validVote1, tampered)
      );
      rejected = !verified;
    } catch (err) {
      rejected = true; // Exception also counts as rejection
    }

    tamperResults.push({ field, rejected });
    printResult(`Tampered '${field}' → rejected`, rejected, rejected);
  }

  const allFieldsRejected = tamperResults.every(r => r.rejected);
  results.tests["4.2_proof_component_tampering"] = {
    fields_tested: proofFields.length,
    all_rejected: allFieldsRejected,
    details: tamperResults,
    pass: allFieldsRejected
  };

  // ─── 4.3  Ciphertext Malleability Attack ────────────────────────
  printSubHeader("4.3  Ciphertext Malleability Attack");

  // Attack: Given E(0) = (c1, c2), compute E(1) = (c1, c2 + G)
  // This exploits ElGamal's additive homomorphism
  const malleable_c2 = validVote0.c2.add(ec.g); // c2' = c2 + G = 0·G + r·h + G = 1·G + r·h
  const malleableCipher = { c1: validVote0.c1, c2: malleable_c2 };

  // Verify the malleability worked (decryption gives m=1 instead of m=0)
  const decryptedMalleable = suppress(() => homomorphic.decrypt(kp.privateKey, malleableCipher));
  const decryptedOriginal = suppress(() => homomorphic.decrypt(kp.privateKey, validVote0));
  
  // Check: the original proof should NOT verify for the malleable ciphertext
  const malleableWithOriginalProof = suppress(() =>
    homomorphic.verifyValidVote(kp.publicKey, malleableCipher, validProof0)
  );

  const malleabilityDetected = !malleableWithOriginalProof;
  
  // The decrypted value should be 1·G (shifted by +1)
  const originalIsZero = decryptedOriginal.isInfinity(); // 0·G = point at infinity
  const malleableIs1G = decryptedMalleable.eq(ec.g);     // 1·G = generator

  results.tests["4.3_ciphertext_malleability"] = {
    original_decrypts_to_zero: originalIsZero,
    malleable_decrypts_to_one: malleableIs1G,
    malleability_successful: malleableIs1G,
    original_proof_rejected_for_malleable: malleabilityDetected,
    zkp_prevents_exploitation: malleabilityDetected,
    pass: malleabilityDetected
  };

  printResult("Original decrypts to 0 (infinity)", originalIsZero, originalIsZero);
  printResult("Malleable decrypts to 1 (G)", malleableIs1G, malleableIs1G);
  printResult("ElGamal IS malleable (by design)", malleableIs1G);
  printResult("Original ZKP rejected for malleable ciphertext", malleabilityDetected, malleabilityDetected);
  printResult("⇒ ZKP prevents malleability exploitation", malleabilityDetected, malleabilityDetected);

  // ─── 4.4  Cross-Vote Proof Reuse ────────────────────────────────
  printSubHeader("4.4  Cross-Vote ZKP Reuse");

  // Try using proof from vote=1 to verify a ciphertext of vote=0
  const crossReuse_0_with_1 = suppress(() =>
    homomorphic.verifyValidVote(kp.publicKey, validVote0, validProof1)
  );
  const crossReuse_1_with_0 = suppress(() =>
    homomorphic.verifyValidVote(kp.publicKey, validVote1, validProof0)
  );

  // Try using proof from one keypair with a different keypair
  const kp2 = suppress(() => homomorphic.generateKeypair());
  const vote1_kp2 = suppress(() => homomorphic.encrypt(kp2.publicKey, 1));
  const crossKey = suppress(() =>
    homomorphic.verifyValidVote(kp2.publicKey, validVote1, validProof1)
  );

  results.tests["4.4_cross_vote_proof_reuse"] = {
    proof1_on_cipher0_rejected: !crossReuse_0_with_1,
    proof0_on_cipher1_rejected: !crossReuse_1_with_0,
    proof_cross_key_rejected: !crossKey,
    pass: !crossReuse_0_with_1 && !crossReuse_1_with_0 && !crossKey
  };

  printResult("Proof for m=1 reused on cipher(m=0) → rejected", !crossReuse_0_with_1, !crossReuse_0_with_1);
  printResult("Proof for m=0 reused on cipher(m=1) → rejected", !crossReuse_1_with_0, !crossReuse_1_with_0);
  printResult("Proof reused with different keypair → rejected", !crossKey, !crossKey);

  // ─── 4.5  Forged Proof from Scratch ─────────────────────────────
  printSubHeader("4.5  Random ZKP Forgery (1,000 trials)");

  const ZKP_FORGERY_TRIALS = 1000;
  let zkpForgeryAccepted = 0;

  for (let i = 0; i < ZKP_FORGERY_TRIALS; i++) {
    // Generate completely random proof components
    const randomProof = {
      a1: (() => { const p = ec.genKeyPair().getPublic(); return { x: p.getX().toString(16), y: p.getY().toString(16) }; })(),
      b1: (() => { const p = ec.genKeyPair().getPublic(); return { x: p.getX().toString(16), y: p.getY().toString(16) }; })(),
      a2: (() => { const p = ec.genKeyPair().getPublic(); return { x: p.getX().toString(16), y: p.getY().toString(16) }; })(),
      b2: (() => { const p = ec.genKeyPair().getPublic(); return { x: p.getX().toString(16), y: p.getY().toString(16) }; })(),
      d1: new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16),
      d2: new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16),
      r1: new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16),
      r2: new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16),
    };

    try {
      const accepted = suppress(() =>
        homomorphic.verifyValidVote(kp.publicKey, validVote1, randomProof)
      );
      if (accepted) zkpForgeryAccepted++;
    } catch (e) {
      // Exception = rejection
    }
  }

  results.tests["4.5_random_zkp_forgery"] = {
    trials: ZKP_FORGERY_TRIALS,
    accepted: zkpForgeryAccepted,
    rejected: ZKP_FORGERY_TRIALS - zkpForgeryAccepted,
    pass: zkpForgeryAccepted === 0
  };

  printResult(
    `Random ZKP forgeries accepted`,
    `${zkpForgeryAccepted}/${ZKP_FORGERY_TRIALS}`,
    zkpForgeryAccepted === 0
  );

  // ─── Summary ──────────────────────────────────────────────────
  printSubHeader("Summary");
  const allTests = Object.values(results.tests);
  const passed = allTests.filter(t => t.pass).length;

  printTable([
    ["Test", "Result"],
    ["4.1 Invalid Vote Values (" + invalidValues.length + ")", results.tests["4.1_invalid_vote_values"].pass ? "PASS" : "FAIL"],
    ["4.2 Proof Component Tamper (8)", results.tests["4.2_proof_component_tampering"].pass ? "PASS" : "FAIL"],
    ["4.3 Ciphertext Malleability", results.tests["4.3_ciphertext_malleability"].pass ? "PASS" : "FAIL"],
    ["4.4 Cross-Vote Proof Reuse", results.tests["4.4_cross_vote_proof_reuse"].pass ? "PASS" : "FAIL"],
    ["4.5 Random ZKP Forgery (1K)", results.tests["4.5_random_zkp_forgery"].pass ? "PASS" : "FAIL"],
  ]);

  console.log(`\n  Overall: ${passed}/${allTests.length} tests passed`);

  saveResults("04_zkp_attack_results.json", results);
  return results;
}

if (require.main === module) {
  run().catch(console.error);
}
module.exports = { run };
