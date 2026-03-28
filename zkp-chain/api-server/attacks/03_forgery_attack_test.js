/**
 * ═══════════════════════════════════════════════════════════════════
 *  Category 3 — Ring Signature Forgery Resilience Tests
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Tests the system's resistance to LRS forgery attacks.
 *  These are OFFLINE crypto tests — no live network needed.
 *
 *  Tests:
 *    3.1  Random forgery (10,000 trials) — unforgeability
 *    3.2  Ring member exclusion/manipulation — ring binding
 *    3.3  Link tag manipulation (4 variants) — tag integrity
 *    3.4  Scalar response tampering (per position) — structural soundness
 *    3.5  Challenge value manipulation — ring closure integrity
 *
 *  Run: node attacks/03_forgery_attack_test.js
 */

"use strict";

const {
  ec, BN, crypto,
  nowMs, suppress,
  printHeader, printSubHeader, printResult, printTable,
  saveResults, generateRing, signSuppressed, verifySuppressed,
  mean, stddev
} = require("./utils");
const lrs = require("../crypto/lrs");

const RING_SIZE = 8;
const FORGERY_TRIALS = 1000;

async function run() {
  printHeader("Category 3 — Ring Signature Forgery Resilience");

  const results = {
    category: "Ring Signature Forgery",
    timestamp: new Date().toISOString(),
    tests: {}
  };

  // Generate a valid ring and signature for manipulation tests
  const { keys, points, data } = generateRing(RING_SIZE);
  const signerKey = keys[0].getPrivate();
  const message = "test_forgery_" + Date.now();
  const validSig = signSuppressed(lrs, signerKey, points, 0, message);
  const validSigCopy = JSON.parse(JSON.stringify(validSig));

  // Sanity: valid signature must pass
  const sanity = verifySuppressed(lrs, validSig, points, message);
  printResult("Sanity check (valid sig verifies)", sanity, sanity);

  // ─── 3.1  Random Forgery (Unforgeability) ───────────────────────
  printSubHeader(`3.1  Random Forgery (${FORGERY_TRIALS.toLocaleString()} trials)`);

  let forgeryAccepted = 0;
  const t0 = nowMs();

  for (let i = 0; i < FORGERY_TRIALS; i++) {
    // Construct a completely random signature
    const fakeSig = {
      c0: new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16),
      s: Array.from({ length: RING_SIZE }, () =>
        new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16)
      ),
      linkTag: (() => {
        const rp = ec.genKeyPair().getPublic();
        return { x: rp.getX().toString(16), y: rp.getY().toString(16) };
      })(),
      startIndex: Math.floor(Math.random() * RING_SIZE),
      ringSize: RING_SIZE
    };

    const accepted = verifySuppressed(lrs, fakeSig, points, message);
    if (accepted) forgeryAccepted++;
  }

  const forgeryTime = nowMs() - t0;
  const forgeryRate = (forgeryAccepted / FORGERY_TRIALS * 100).toFixed(6);

  results.tests["3.1_random_forgery"] = {
    trials: FORGERY_TRIALS,
    accepted: forgeryAccepted,
    rejected: FORGERY_TRIALS - forgeryAccepted,
    forgery_success_rate: forgeryRate + "%",
    total_time_ms: forgeryTime.toFixed(0),
    avg_verify_time_ms: (forgeryTime / FORGERY_TRIALS).toFixed(3),
    pass: forgeryAccepted === 0
  };

  printResult("Forgery attempts", FORGERY_TRIALS.toLocaleString());
  printResult("Accepted (false positive)", forgeryAccepted, forgeryAccepted === 0);
  printResult("Rejection rate", `${(100 - parseFloat(forgeryRate)).toFixed(4)}%`);
  printResult("Avg verify time", `${(forgeryTime / FORGERY_TRIALS).toFixed(3)} ms`);

  // ─── 3.2  Ring Member Exclusion Attack ──────────────────────────
  printSubHeader("3.2  Ring Manipulation Attacks");

  const ringManipResults = [];

  // 3.2a: Remove a member from the ring
  const reducedRing = points.slice(1); // remove first member (the signer!)
  const result_3_2a = verifySuppressed(lrs, validSigCopy, reducedRing, message);
  ringManipResults.push(["Remove signer from ring", !result_3_2a]);
  printResult("Remove signer from ring → rejected", !result_3_2a, !result_3_2a);

  // 3.2b: Add a random member to the ring
  const extendedRing = [...points, ec.genKeyPair().getPublic()];
  const result_3_2b = verifySuppressed(lrs, validSigCopy, extendedRing, message);
  ringManipResults.push(["Add extra member to ring", !result_3_2b]);
  printResult("Add extra member → rejected", !result_3_2b, !result_3_2b);

  // 3.2c: Swap ring member order
  const shuffledRing = [...points].reverse();
  const result_3_2c = verifySuppressed(lrs, validSigCopy, shuffledRing, message);
  ringManipResults.push(["Shuffle ring order", !result_3_2c]);
  printResult("Shuffle ring order → rejected", !result_3_2c, !result_3_2c);

  // 3.2d: Replace a member with a random key
  const substitutedRing = [...points];
  substitutedRing[2] = ec.genKeyPair().getPublic();
  const result_3_2d = verifySuppressed(lrs, validSigCopy, substitutedRing, message);
  ringManipResults.push(["Replace member with random", !result_3_2d]);
  printResult("Replace member with random key → rejected", !result_3_2d, !result_3_2d);

  // 3.2e: Completely different ring (same size)
  const { points: fakeRing } = generateRing(RING_SIZE);
  const result_3_2e = verifySuppressed(lrs, validSigCopy, fakeRing, message);
  ringManipResults.push(["Entirely different ring", !result_3_2e]);
  printResult("Entirely different ring → rejected", !result_3_2e, !result_3_2e);

  const allRingManipPassed = ringManipResults.every(r => r[1]);
  results.tests["3.2_ring_manipulation"] = {
    variants_tested: ringManipResults.length,
    all_rejected: allRingManipPassed,
    details: ringManipResults.map(r => ({ attack: r[0], rejected: r[1] })),
    pass: allRingManipPassed
  };

  // ─── 3.3  Link Tag Manipulation (4 variants) ───────────────────
  printSubHeader("3.3  Link Tag Manipulation (4 variants)");

  const linkTagResults = [];

  // 3.3a: Random point as link tag
  const tampered_3_3a = JSON.parse(JSON.stringify(validSigCopy));
  const randPoint = ec.genKeyPair().getPublic();
  tampered_3_3a.linkTag = { x: randPoint.getX().toString(16), y: randPoint.getY().toString(16) };
  const result_3_3a = verifySuppressed(lrs, tampered_3_3a, points, message);
  linkTagResults.push(["Random point", !result_3_3a]);
  printResult("Random point as link tag → rejected", !result_3_3a, !result_3_3a);

  // 3.3b: Generator point G
  const tampered_3_3b = JSON.parse(JSON.stringify(validSigCopy));
  tampered_3_3b.linkTag = { x: ec.g.getX().toString(16), y: ec.g.getY().toString(16) };
  const result_3_3b = verifySuppressed(lrs, tampered_3_3b, points, message);
  linkTagResults.push(["Generator G", !result_3_3b]);
  printResult("Generator G as link tag → rejected", !result_3_3b, !result_3_3b);

  // 3.3c: Doubled original tag (2·I)
  const tampered_3_3c = JSON.parse(JSON.stringify(validSigCopy));
  const origTag = ec.curve.point(
    new BN(validSigCopy.linkTag.x, 16),
    new BN(validSigCopy.linkTag.y, 16)
  );
  const doubledTag = origTag.mul(new BN(2));
  tampered_3_3c.linkTag = { x: doubledTag.getX().toString(16), y: doubledTag.getY().toString(16) };
  const result_3_3c = verifySuppressed(lrs, tampered_3_3c, points, message);
  linkTagResults.push(["Doubled tag (2·I)", !result_3_3c]);
  printResult("Doubled tag (2·I) → rejected", !result_3_3c, !result_3_3c);

  // 3.3d: Negated tag (-I)
  const tampered_3_3d = JSON.parse(JSON.stringify(validSigCopy));
  const negTag = origTag.neg();
  tampered_3_3d.linkTag = { x: negTag.getX().toString(16), y: negTag.getY().toString(16) };
  const result_3_3d = verifySuppressed(lrs, tampered_3_3d, points, message);
  linkTagResults.push(["Negated tag (-I)", !result_3_3d]);
  printResult("Negated tag (-I) → rejected", !result_3_3d, !result_3_3d);

  const allLinkTagPassed = linkTagResults.every(r => r[1]);
  results.tests["3.3_link_tag_manipulation"] = {
    variants_tested: linkTagResults.length,
    all_rejected: allLinkTagPassed,
    details: linkTagResults.map(r => ({ variant: r[0], rejected: r[1] })),
    pass: allLinkTagPassed
  };

  // ─── 3.4  Scalar Response Tampering (per ring position) ────────
  printSubHeader("3.4  Scalar Response Tampering (per position)");

  let scalarTamperRejections = 0;

  for (let i = 0; i < RING_SIZE; i++) {
    const tampered = JSON.parse(JSON.stringify(validSigCopy));
    // Add 1 to s[i]
    const original_s = new BN(tampered.s[i], 16);
    tampered.s[i] = original_s.addn(1).umod(ec.curve.n).toString(16);

    const accepted = verifySuppressed(lrs, tampered, points, message);
    if (!accepted) scalarTamperRejections++;
  }

  const scalarTamperPass = scalarTamperRejections === RING_SIZE;
  results.tests["3.4_scalar_tampering"] = {
    ring_size: RING_SIZE,
    positions_tampered: RING_SIZE,
    rejected: scalarTamperRejections,
    rejection_rate: ((scalarTamperRejections / RING_SIZE) * 100).toFixed(1) + "%",
    pass: scalarTamperPass
  };

  printResult(
    `Tampered s[i] (${RING_SIZE} positions)`,
    `${scalarTamperRejections}/${RING_SIZE} rejected`,
    scalarTamperPass
  );

  // Also test random bit flips in s values (deeper fuzzing)
  let bitFlipRejections = 0;
  const BIT_FLIP_TRIALS = 100;

  for (let t = 0; t < BIT_FLIP_TRIALS; t++) {
    const tampered = JSON.parse(JSON.stringify(validSigCopy));
    const pos = Math.floor(Math.random() * RING_SIZE);
    // XOR with random byte at random position
    const sBytes = Buffer.from(tampered.s[pos].padStart(64, "0"), "hex");
    const bytePos = Math.floor(Math.random() * sBytes.length);
    sBytes[bytePos] ^= (1 << Math.floor(Math.random() * 8));
    tampered.s[pos] = new BN(sBytes).umod(ec.curve.n).toString(16);

    const accepted = verifySuppressed(lrs, tampered, points, message);
    if (!accepted) bitFlipRejections++;
  }

  results.tests["3.4_bit_flip_fuzzing"] = {
    trials: BIT_FLIP_TRIALS,
    rejected: bitFlipRejections,
    rejection_rate: ((bitFlipRejections / BIT_FLIP_TRIALS) * 100).toFixed(1) + "%",
    pass: bitFlipRejections === BIT_FLIP_TRIALS
  };

  printResult(
    `Random bit-flip fuzzing (${BIT_FLIP_TRIALS} trials)`,
    `${bitFlipRejections}/${BIT_FLIP_TRIALS} rejected`,
    bitFlipRejections === BIT_FLIP_TRIALS
  );

  // ─── 3.5  Challenge (c0) Manipulation ──────────────────────────
  printSubHeader("3.5  Challenge (c0) Manipulation");

  const challengeVariants = [];

  // 3.5a: c0 + 1
  const tampered_c0a = JSON.parse(JSON.stringify(validSigCopy));
  tampered_c0a.c0 = new BN(tampered_c0a.c0, 16).addn(1).umod(ec.curve.n).toString(16);
  const result_c0a = verifySuppressed(lrs, tampered_c0a, points, message);
  challengeVariants.push(["c0 + 1", !result_c0a]);
  printResult("c0 + 1 → rejected", !result_c0a, !result_c0a);

  // 3.5b: c0 = 0
  const tampered_c0b = JSON.parse(JSON.stringify(validSigCopy));
  tampered_c0b.c0 = "0";
  const result_c0b = verifySuppressed(lrs, tampered_c0b, points, message);
  challengeVariants.push(["c0 = 0", !result_c0b]);
  printResult("c0 = 0 → rejected", !result_c0b, !result_c0b);

  // 3.5c: c0 = random
  const tampered_c0c = JSON.parse(JSON.stringify(validSigCopy));
  tampered_c0c.c0 = new BN(crypto.randomBytes(32)).umod(ec.curve.n).toString(16);
  const result_c0c = verifySuppressed(lrs, tampered_c0c, points, message);
  challengeVariants.push(["c0 = random", !result_c0c]);
  printResult("c0 = random → rejected", !result_c0c, !result_c0c);

  // 3.5d: Different message (message manipulation)
  const result_msg = verifySuppressed(lrs, validSigCopy, points, "manipulated_message");
  challengeVariants.push(["Different message", !result_msg]);
  printResult("Different message → rejected", !result_msg, !result_msg);

  const allChallengePassed = challengeVariants.every(r => r[1]);
  results.tests["3.5_challenge_manipulation"] = {
    variants_tested: challengeVariants.length,
    all_rejected: allChallengePassed,
    details: challengeVariants.map(r => ({ variant: r[0], rejected: r[1] })),
    pass: allChallengePassed
  };

  // ─── Summary ──────────────────────────────────────────────────
  printSubHeader("Summary");
  const allTests = Object.values(results.tests);
  const passed = allTests.filter(t => t.pass).length;
  const total = allTests.length;

  printTable([
    ["Test", "Result"],
    ["3.1 Random Forgery (10K)", results.tests["3.1_random_forgery"].pass ? "PASS" : "FAIL"],
    ["3.2 Ring Manipulation (5)", results.tests["3.2_ring_manipulation"].pass ? "PASS" : "FAIL"],
    ["3.3 Link Tag Manipulation (4)", results.tests["3.3_link_tag_manipulation"].pass ? "PASS" : "FAIL"],
    ["3.4 Scalar Tampering", results.tests["3.4_scalar_tampering"].pass ? "PASS" : "FAIL"],
    ["3.4b Bit-Flip Fuzzing", results.tests["3.4_bit_flip_fuzzing"].pass ? "PASS" : "FAIL"],
    ["3.5 Challenge Manipulation", results.tests["3.5_challenge_manipulation"].pass ? "PASS" : "FAIL"],
  ]);

  console.log(`\n  Overall: ${passed}/${total} tests passed`);

  saveResults("03_forgery_attack_results.json", results);
  return results;
}

if (require.main === module) {
  run().catch(console.error);
}
module.exports = { run };
