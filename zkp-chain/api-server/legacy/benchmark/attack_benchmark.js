/**
 * ═══════════════════════════════════════════════════════════════════
 *  ZKP Voting — Security Attack Resilience Benchmark
 * ═══════════════════════════════════════════════════════════════════
 *
 *  UPDATED: This is now a thin wrapper around the per-category
 *  attack test scripts in the attacks/ directory.
 *
 *  For granular control, run individual categories:
 *    node attacks/01_sybil_attack_test.js     (needs Fabric)
 *    node attacks/02_replay_attack_test.js    (needs Fabric)
 *    node attacks/03_forgery_attack_test.js   (offline)
 *    node attacks/04_zkp_attack_test.js       (offline)
 *    node attacks/05_dos_attack_test.js       (needs API server)
 *    node attacks/06_mitm_attack_test.js      (offline)
 *    node attacks/07_collusion_attack_test.js (offline)
 *    node attacks/08_timing_attack_test.js    (offline)
 *
 *  Or use the orchestrator:
 *    node attacks/run_all_attacks.js              # all tests
 *    node attacks/run_all_attacks.js --offline     # crypto tests only
 *    node attacks/run_all_attacks.js --live        # live system tests only
 *
 *  Generate figures:
 *    python attacks/attack_plot.py
 */

"use strict";

const { runAll } = require("../attacks/run_all_attacks");

// Determine mode from CLI args
const args = process.argv.slice(2);
let mode = "all";

if (args.includes("--offline-only") || args.includes("--offline")) {
  mode = "offline-only";
} else if (args.includes("--live-only") || args.includes("--live")) {
  mode = "live-only";
}

runAll(mode).catch(console.error);
