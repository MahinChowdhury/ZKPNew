/**
 * ═══════════════════════════════════════════════════════════════════
 *  Security Attack Test Runner — All Categories
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Runs all 8 categories of security attack resilience tests and
 *  generates a combined results file for the paper.
 *
 *  Usage:
 *    node attacks/run_all_attacks.js                  # Run all (offline + live)
 *    node attacks/run_all_attacks.js --offline-only    # Offline crypto tests only
 *    node attacks/run_all_attacks.js --live-only       # Live system tests only
 *
 *  Offline tests (no infrastructure needed):
 *    03 — Forgery, 04 — ZKP, 06 — MitM, 07 — Collusion, 08 — Timing
 *
 *  Live tests (require Fabric + API):
 *    01 — Sybil, 02 — Replay, 05 — DoS
 */

"use strict";

const fs = require("fs");
const path = require("path");

const { printHeader, printTable, saveResults } = require("./utils");

// ── Import all test modules ─────────────────────────────────────────
const offlineTests = {
  "03_forgery": require("./03_forgery_attack_test"),
  "04_zkp": require("./04_zkp_attack_test"),
  "06_mitm": require("./06_mitm_attack_test"),
  "07_collusion": require("./07_collusion_attack_test"),
  "08_timing": require("./08_timing_attack_test"),
};

const liveTests = {
  "01_sybil": require("./01_sybil_attack_test"),
  "02_replay": require("./02_replay_attack_test"),
  "05_dos": require("./05_dos_attack_test"),
};

async function runAll(mode = "all") {
  const startTime = Date.now();

  printHeader("🛡️  ZKP Voting — Security Attack Resilience Test Suite");
  console.log(`  Mode: ${mode}`);
  console.log(`  Started: ${new Date().toISOString()}\n`);

  const combinedResults = {
    timestamp: new Date().toISOString(),
    mode,
    categories: {},
    summary: {}
  };

  // Determine which tests to run
  let testsToRun = {};
  if (mode === "offline-only") {
    testsToRun = offlineTests;
  } else if (mode === "live-only") {
    testsToRun = liveTests;
  } else {
    // Run offline first, then live
    testsToRun = { ...offlineTests, ...liveTests };
  }

  // Run tests sequentially
  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;

  for (const [name, testModule] of Object.entries(testsToRun)) {
    console.log(`\n${"━".repeat(70)}`);
    console.log(`  Running: ${name}`);
    console.log(`${"━".repeat(70)}`);

    try {
      const result = await testModule.run();
      combinedResults.categories[name] = result;

      // Count pass/fail
      if (result && result.tests) {
        for (const test of Object.values(result.tests)) {
          totalTests++;
          if (test.pass) totalPassed++;
          else totalFailed++;
        }
      }
    } catch (err) {
      console.error(`  ❌ ${name} failed with error:`, err.message);
      combinedResults.categories[name] = {
        error: err.message,
        tests: {}
      };
    }
  }

  // ── Combined Summary ────────────────────────────────────────────
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  printHeader("📊 Combined Security Attack Results");

  // Build summary table
  const summaryRows = [["Category", "Tests", "Passed", "Failed", "Rate"]];

  for (const [name, result] of Object.entries(combinedResults.categories)) {
    if (result.error) {
      summaryRows.push([name, "ERROR", "-", "-", result.error.slice(0, 30)]);
      continue;
    }
    const tests = Object.values(result.tests || {});
    const p = tests.filter(t => t.pass).length;
    const f = tests.filter(t => !t.pass).length;
    const rate = tests.length > 0
      ? `${((p / tests.length) * 100).toFixed(0)}%`
      : "N/A";
    summaryRows.push([name, tests.length, p, f, rate]);
  }

  printTable(summaryRows);

  combinedResults.summary = {
    total_tests: totalTests,
    passed: totalPassed,
    failed: totalFailed,
    pass_rate: totalTests > 0
      ? `${((totalPassed / totalTests) * 100).toFixed(1)}%`
      : "N/A",
    elapsed_seconds: elapsed
  };

  console.log(`\n  Total: ${totalPassed}/${totalTests} passed (${combinedResults.summary.pass_rate})`);
  console.log(`  Time: ${elapsed}s`);

  // ── Build paper-ready attack matrix ─────────────────────────────
  const attackMatrix = buildAttackMatrix(combinedResults);
  combinedResults.attack_matrix = attackMatrix;

  saveResults("combined_attack_results.json", combinedResults);

  // Also save the attack matrix as a standalone file for easy reference
  saveResults("attack_matrix.json", attackMatrix);

  console.log("\n  Run: python attacks/attack_plot.py  to generate figures\n");

  return combinedResults;
}

function buildAttackMatrix(combinedResults) {
  const matrix = [];

  // Map test results to paper-ready format
  const mappings = [
    { id: 1, attack: "Sybil Registration", layer: "Chaincode", property: "Eligibility", cat: "01_sybil", test: "1.1_sybil_registration" },
    { id: 2, attack: "Duplicate Key Injection", layer: "Chaincode", property: "Uniqueness", cat: "01_sybil", test: "1.2_duplicate_key_injection" },
    { id: 3, attack: "Outsider Key Attack", layer: "API + LRS", property: "Eligibility", cat: "01_sybil", test: "1.3_outsider_voting" },
    { id: 4, attack: "Concurrent Replay", layer: "Chaincode", property: "Revote Prevention", cat: "02_replay", test: "2.1_concurrent_replay" },
    { id: 5, attack: "Re-sign Same Key", layer: "Chaincode", property: "Linkability", cat: "02_replay", test: "2.2_resign_same_key" },
    { id: 6, attack: "Sequential Replay", layer: "Chaincode", property: "Idempotency", cat: "02_replay", test: "2.3_sequential_replay" },
    { id: 7, attack: "Random Forgery (10K)", layer: "LRS", property: "Unforgeability", cat: "03_forgery", test: "3.1_random_forgery" },
    { id: 8, attack: "Ring Manipulation", layer: "LRS", property: "Ring Binding", cat: "03_forgery", test: "3.2_ring_manipulation" },
    { id: 9, attack: "Link Tag Tampering", layer: "LRS", property: "Integrity", cat: "03_forgery", test: "3.3_link_tag_manipulation" },
    { id: 10, attack: "Scalar Tampering", layer: "LRS", property: "Soundness", cat: "03_forgery", test: "3.4_scalar_tampering" },
    { id: 11, attack: "Bit-Flip Fuzzing", layer: "LRS", property: "Robustness", cat: "03_forgery", test: "3.4_bit_flip_fuzzing" },
    { id: 12, attack: "Challenge Manipulation", layer: "LRS", property: "Ring Closure", cat: "03_forgery", test: "3.5_challenge_manipulation" },
    { id: 13, attack: "Invalid Vote Values", layer: "ZKP", property: "Soundness", cat: "04_zkp", test: "4.1_invalid_vote_values" },
    { id: 14, attack: "ZKP Component Tamper", layer: "ZKP", property: "Soundness", cat: "04_zkp", test: "4.2_proof_component_tampering" },
    { id: 15, attack: "Ciphertext Malleability", layer: "ElGamal+ZKP", property: "Integrity", cat: "04_zkp", test: "4.3_ciphertext_malleability" },
    { id: 16, attack: "Cross-Vote Proof Reuse", layer: "ZKP", property: "Binding", cat: "04_zkp", test: "4.4_cross_vote_proof_reuse" },
    { id: 17, attack: "Random ZKP Forgery", layer: "ZKP", property: "Unforgeability", cat: "04_zkp", test: "4.5_random_zkp_forgery" },
    { id: 18, attack: "DoS Flood", layer: "API", property: "Availability", cat: "05_dos", test: "5.1_malformed_flood" },
    { id: 19, attack: "Valid-Looking Flood", layer: "API", property: "Validation", cat: "05_dos", test: "5.2_valid_looking_flood" },
    { id: 20, attack: "Large Payload", layer: "API", property: "Resource Safety", cat: "05_dos", test: "5.3_large_payload" },
    { id: 21, attack: "Private Key Exposure", layer: "API", property: "Confidentiality", cat: "05_dos", test: "5.4_unauthorized_access" },
    { id: 22, attack: "Vote Modification", layer: "LRS+ElGamal", property: "Integrity", cat: "06_mitm", test: "6.1_vote_modification_detection" },
    { id: 23, attack: "Vector Swap", layer: "LRS+ElGamal", property: "Binding", cat: "06_mitm", test: "6.2_encrypted_vector_swap" },
    { id: 24, attack: "PK Substitution", layer: "ElGamal", property: "Confidentiality", cat: "06_mitm", test: "6.3_public_key_substitution" },
    { id: 25, attack: "Partial Replay", layer: "LRS+Hash", property: "Integrity", cat: "06_mitm", test: "6.4_partial_replay" },
    { id: 26, attack: "n-1 Collusion", layer: "LRS", property: "Anonymity", cat: "07_collusion", test: "7.1_n_minus_1_collusion" },
    { id: 27, attack: "Authority Key Abuse", layer: "ElGamal", property: "Secrecy", cat: "07_collusion", test: "7.2_authority_key_abuse" },
    { id: 28, attack: "Cross-Election Link", layer: "LRS", property: "Unlinkability", cat: "07_collusion", test: "7.3_cross_election_linkability" },
    { id: 29, attack: "Signer Position Timing", layer: "LRS", property: "Side-Channel", cat: "08_timing", test: "8.1_signer_position_timing" },
    { id: 30, attack: "Vote Value Timing", layer: "ElGamal+ZKP", property: "Side-Channel", cat: "08_timing", test: "8.2_vote_value_timing" },
  ];

  for (const m of mappings) {
    const catResult = combinedResults.categories[m.cat];
    let status = "NOT RUN";
    let detail = {};

    if (catResult && catResult.tests && catResult.tests[m.test]) {
      const t = catResult.tests[m.test];
      status = t.pass ? "PASS" : "FAIL";
      detail = t;
    } else if (catResult && catResult.error) {
      status = "ERROR";
    }

    matrix.push({
      id: m.id,
      attack: m.attack,
      layer: m.layer,
      property: m.property,
      status,
      detail
    });
  }

  return matrix;
}

// ── CLI handling ─────────────────────────────────────────────────────
if (require.main === module) {
  const args = process.argv.slice(2);
  let mode = "all";

  if (args.includes("--offline-only") || args.includes("--offline")) {
    mode = "offline-only";
  } else if (args.includes("--live-only") || args.includes("--live")) {
    mode = "live-only";
  }

  runAll(mode).catch(console.error);
}

module.exports = { runAll };
