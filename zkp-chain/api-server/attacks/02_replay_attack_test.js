/**
 * ═══════════════════════════════════════════════════════════════════
 *  Category 2 — Replay & Double-Voting Attack Tests
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Tests the system's resistance to replay and double-voting attacks.
 *  ⚠️  LIVE SYSTEM TESTS — Requires Fabric network running.
 *
 *  Tests:
 *    2.1  Link tag replay at various concurrency levels
 *    2.2  Re-sign with same key (different signature, same link tag)
 *    2.3  Sequential double-vote attempts
 *
 *  Run: node attacks/02_replay_attack_test.js
 *  Requires: Fabric test-network running
 */

"use strict";

const {
  ec, BN, crypto,
  nowMs, suppress, suppressAsync,
  printHeader, printSubHeader, printResult, printTable,
  saveResults, generateRing, signSuppressed
} = require("./utils");
const lrs = require("../crypto/lrs");
const FabricClient = require("../fabric-client");

const RUN_ID = Date.now().toString(36);

async function run() {
  printHeader("Category 2 — Replay & Double-Voting Attack Tests (Live Fabric)");

  const results = {
    category: "Replay & Double-Voting",
    timestamp: new Date().toISOString(),
    requires_live_system: true,
    tests: {}
  };

  // Connect to Fabric
  const fc = new FabricClient();
  try {
    await suppressAsync(() => fc.connect());
    console.log("  ✅ Connected to Fabric network\n");
  } catch (e) {
    console.error("  ❌ Fabric connection failed. Start the network first.");
    results.error = "Fabric connection failed: " + e.message;
    saveResults("02_replay_attack_results.json", results);
    return results;
  }

  // Setup: create a ring for testing
  const { keys, points, data: ringData } = generateRing(6);

  // ─── 2.1  Concurrent Link Tag Replay Attack ────────────────────
  printSubHeader("2.1  Concurrent Link Tag Replay at Various Concurrency Levels");

  const CONCURRENCY_LEVELS = [1, 5, 10, 25, 50];
  const replayResults = [];

  for (const concurrency of CONCURRENCY_LEVELS) {
    const msg = crypto.createHash("sha256")
      .update(`replay_2_1_c${concurrency}_${RUN_ID}`)
      .digest("hex");

    // Generate a valid signature
    const sig = signSuppressed(lrs, keys[0].getPrivate(), points, 0, msg);

    let successfulCommits = 0;
    let doubleVoteRejections = 0;
    let otherErrors = 0;

    const startTime = nowMs();
    const promises = [];

    for (let i = 0; i < concurrency; i++) {
      promises.push(
        suppressAsync(() => fc.castVote(sig, ringData, null))
          .then(() => { successfulCommits++; })
          .catch((err) => {
            if (err.message && (
              err.message.includes("Double voting") ||
              err.message.includes("already voted") ||
              err.message.includes("MVCC_READ_CONFLICT")
            )) {
              doubleVoteRejections++;
            } else {
              otherErrors++;
            }
          })
      );
    }

    await Promise.allSettled(promises);
    const duration = nowMs() - startTime;

    const entry = {
      concurrency,
      successful_commits: successfulCommits,
      double_vote_rejections: doubleVoteRejections,
      other_errors: otherErrors,
      duration_ms: duration.toFixed(0),
      pass: successfulCommits <= 1
    };
    replayResults.push(entry);

    printResult(
      `Concurrency=${concurrency}`,
      `commits=${successfulCommits}, rejected=${doubleVoteRejections}, errors=${otherErrors} (${duration.toFixed(0)}ms)`,
      successfulCommits <= 1
    );
  }

  results.tests["2.1_concurrent_replay"] = {
    concurrency_levels: CONCURRENCY_LEVELS,
    results: replayResults,
    pass: replayResults.every(r => r.pass)
  };

  // ─── 2.2  Re-sign with Same Key (Same Link Tag) ───────────────
  printSubHeader("2.2  Re-sign Attack — Different Signature, Same Link Tag");

  const RESIGN_ATTEMPTS = 10;
  let resignSuccesses = 0;
  let resignRejections = 0;

  // First message and signature (should succeed)
  const firstMsg = crypto.createHash("sha256")
    .update(`resign_first_${RUN_ID}`)
    .digest("hex");
  const firstSig = signSuppressed(lrs, keys[1].getPrivate(), points, 1, firstMsg);

  let firstCommitOk = false;
  try {
    await suppressAsync(() => fc.castVote(firstSig, ringData, null));
    firstCommitOk = true;
  } catch (e) {
    firstCommitOk = false;
  }

  printResult("First vote (unique) commits", firstCommitOk, firstCommitOk);

  // Now re-sign the same key with different messages
  // The link tag is deterministic: I = k·H(P), so it's always the same
  for (let i = 0; i < RESIGN_ATTEMPTS; i++) {
    const differentMsg = crypto.createHash("sha256")
      .update(`resign_${i}_${RUN_ID}`)
      .digest("hex");
    const newSig = signSuppressed(lrs, keys[1].getPrivate(), points, 1, differentMsg);

    // Verify link tags are indeed the same
    const sameTag = newSig.linkTag.x === firstSig.linkTag.x &&
                    newSig.linkTag.y === firstSig.linkTag.y;

    if (!sameTag) {
      console.log("  ⚠️  WARNING: Link tags differ across signatures!");
    }

    try {
      await suppressAsync(() => fc.castVote(newSig, ringData, null));
      resignSuccesses++;
    } catch (e) {
      if (e.message && (
        e.message.includes("Double voting") ||
        e.message.includes("already voted")
      )) {
        resignRejections++;
      }
    }
  }

  const resignPass = resignSuccesses === 0;
  results.tests["2.2_resign_same_key"] = {
    first_commit: firstCommitOk,
    resign_attempts: RESIGN_ATTEMPTS,
    successful_commits: resignSuccesses,
    double_vote_rejections: resignRejections,
    link_tag_is_deterministic: true,
    pass: resignPass
  };

  printResult(
    `Re-sign attempts rejected`,
    `${resignRejections}/${RESIGN_ATTEMPTS}`,
    resignPass
  );

  // ─── 2.3  Sequential Double-Vote (Same Exact Signature) ───────
  printSubHeader("2.3  Sequential Double-Vote — Exact Replay");

  const seqMsg = crypto.createHash("sha256")
    .update(`seq_replay_${RUN_ID}`)
    .digest("hex");
  const seqSig = signSuppressed(lrs, keys[2].getPrivate(), points, 2, seqMsg);

  let seqFirstOk = false;
  try {
    await suppressAsync(() => fc.castVote(seqSig, ringData, null));
    seqFirstOk = true;
  } catch (e) {
    seqFirstOk = false;
  }

  printResult("Sequential: 1st submission", seqFirstOk ? "accepted" : "rejected", seqFirstOk);

  const SEQ_REPLAYS = 5;
  let seqRejections = 0;
  for (let i = 0; i < SEQ_REPLAYS; i++) {
    try {
      await suppressAsync(() => fc.castVote(seqSig, ringData, null));
    } catch (e) {
      seqRejections++;
    }
  }

  const seqPass = seqRejections === SEQ_REPLAYS;
  results.tests["2.3_sequential_replay"] = {
    first_accepted: seqFirstOk,
    replay_attempts: SEQ_REPLAYS,
    rejected: seqRejections,
    pass: seqPass
  };

  printResult(
    `Sequential replays rejected`,
    `${seqRejections}/${SEQ_REPLAYS}`,
    seqPass
  );

  // ─── Summary ──────────────────────────────────────────────────
  printSubHeader("Summary");
  const allTests = Object.values(results.tests);
  const passed = allTests.filter(t => t.pass).length;

  printTable([
    ["Test", "Result"],
    ["2.1 Concurrent Replay", results.tests["2.1_concurrent_replay"].pass ? "PASS" : "FAIL"],
    ["2.2 Re-sign Same Key", results.tests["2.2_resign_same_key"].pass ? "PASS" : "FAIL"],
    ["2.3 Sequential Replay", results.tests["2.3_sequential_replay"].pass ? "PASS" : "FAIL"],
  ]);

  console.log(`\n  Overall: ${passed}/${allTests.length} tests passed`);

  // Cleanup
  if (fc.gateway) {
    await fc.gateway.disconnect();
  }

  saveResults("02_replay_attack_results.json", results);
  return results;
}

if (require.main === module) {
  run().catch(console.error);
}
module.exports = { run };
