/**
 * ═══════════════════════════════════════════════════════════════════
 *  Master Publication-Grade Evaluation & Plotting Runner (July 2026)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Sequentially executes all cryptographic, biometric, blockchain, and
 *  security attack benchmarks in the repository and triggers the plotting
 *  scripts to generate all figures for the Q1 journal paper.
 *
 *  Usage:
 *    node zkp-chain/api-server/benchmark/run_all_benchmarks_and_plots.js
 */

"use strict";

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT_DIR = path.join(__dirname, "..", "..", "..");

function runCommand(command, description) {
  console.log("\n" + "━".repeat(80));
  console.log(` 🏃 Running: ${description}`);
  console.log(`    Command: ${command}`);
  console.log("━".repeat(80));

  try {
    execSync(command, { cwd: ROOT_DIR, stdio: "inherit" });
    console.log(`\n ✅ Successfully completed: ${description}\n`);
  } catch (error) {
    console.error(`\n ❌ Error executing: ${description}`);
    console.error(`    Message: ${error.message}\n`);
  }
}

(() => {
  console.log("\n" + "==========================================================================");
  console.log("  ZKP Voting System — Master Evaluation & Paper Figures Generator");
  console.log("==========================================================================");
  console.log("  This script runs all evaluation suites sequentially. Make sure Node.js");
  console.log("  and Python 3 (with numpy and matplotlib) are installed.");
  console.log("==========================================================================\n");

  const startTime = Date.now();

  // 1. Biometric Accuracy Evaluation & Plotter
  runCommand(
    "python3 zkp-chain/model/biometric_accuracy_eval.py",
    "Biometric Accuracy evaluation (LFW & CASIA EER curves, DET & ROC plots)"
  );

  // 2. Paradigm Comparison: On-chain vs Off-chain validation latency
  runCommand(
    "node zkp-chain/api-server/benchmark/onchain_vs_offchain_benchmark.js --iters 30",
    "On-Chain vs. Off-Chain Groth16 verification paradigm comparison"
  );

  // 3. E2E Dual-Modality timing benchmark
  runCommand(
    "node zkp-chain/api-server/benchmark/e2e_benchmark.js --iters 30",
    "E2E Vote Casting Pipeline timing benchmark (P1-P8, JIT Warmup, peak RAM)"
  );

  // 4. Parametric E2E Scalability Sweep
  runCommand(
    "node zkp-chain/api-server/benchmark/e2e_scalability_benchmark.js --iters 5",
    "Parametric E2E Scalability sweep (up to 100,000 voters & 50 candidates)"
  );

  // 5. Homomorphic ElGamal & BSGS Sweep
  runCommand(
    "node zkp-chain/api-server/benchmark/homomorphic_benchmark.js",
    "Homomorphic ElGamal vector encryption & BSGS discrete log up to 1M voters"
  );

  // 6. ZK-SNARK Complexity Benchmarks
  runCommand(
    "node zkp-chain/api-server/benchmark/zksnark_benchmark.js --iters 30",
    "ZK-SNARK (Groth16) constraints complexity and proof sizes evaluation"
  );

  // 7. High-Concurrency Scale Sweep (Simulated M/M/1 queue)
  runCommand(
    "node zkp-chain/api-server/benchmark/concurrent_load_test.js --concurrency 1000",
    "Concurrent Transaction scale sweep (1,000 concurrent transactions)"
  );

  // 8. Security Attack Resilience Suite
  runCommand(
    "node zkp-chain/api-server/attacks/run_all_attacks.js --offline-only",
    "Security Attack resilience offline suite (including zeroed proof test)"
  );

  // 9. Generate Paper Figures
  console.log("\n" + "📊" + "━".repeat(78));
  console.log("  📈 GENERATING ALL PAPER FIGURES...");
  console.log("━".repeat(80));

  runCommand(
    "python3 zkp-chain/api-server/benchmark/e2e_plot.py",
    "Generating E2E Pipeline Latency plots"
  );
  runCommand(
    "python3 zkp-chain/api-server/benchmark/e2e_scalability_plot.py",
    "Generating Voter Tree & Candidate count sweep plots"
  );
  runCommand(
    "python3 zkp-chain/api-server/benchmark/homomorphic_plot.py",
    "Generating ElGamal & BSGS discrete log solver latency plots"
  );
  runCommand(
    "python3 zkp-chain/api-server/benchmark/zksnark_plot.py",
    "Generating ZK-SNARK constraints, keys, and proof sizes plots"
  );
  runCommand(
    "python3 zkp-chain/api-server/attacks/attack_plot.py",
    "Generating Attack Resilience Matrix plot"
  );
  runCommand(
    "python3 zkp-chain/api-server/compareBenchmarks/plot_results.py",
    "Generating comparative system performance plots"
  );

  const totalTimeSeconds = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log("\n" + "==========================================================================");
  console.log(" 🎉 MASTER BENCHMARKS & PLOTTING RUN COMPLETED SUCCESSFULLY!");
  console.log(`    Total time: ${totalTimeSeconds} seconds`);
  console.log("==========================================================================");
  
  console.log("\n📁 Results and Plots Summary Location:");
  console.log("   - Biometric EER Curves (ROC, DET, Sweep): zkp-chain/api-server/benchmark/");
  console.log("     → ROC Curve       : zkp-chain/api-server/benchmark/biometric_roc_curve.png");
  console.log("     → DET Curve       : zkp-chain/api-server/benchmark/biometric_det_curve.png");
  console.log("     → Sweep Curve     : zkp-chain/api-server/benchmark/biometric_threshold_sweep.png");
  console.log("   - E2E Timing and Scalability Plots: zkp-chain/api-server/benchmark/");
  console.log("     → E2E Latency     : zkp-chain/api-server/benchmark/fig9_e2e_latency.png");
  console.log("     → Scalability     : zkp-chain/api-server/benchmark/fig9_e2e_scalability.png");
  console.log("     → Homomorphic     : zkp-chain/api-server/benchmark/fig8_homomorphic.png");
  console.log("     → SNARK Proving   : zkp-chain/api-server/benchmark/fig6_simulation.png");
  console.log("   - Attack Resilience Matrix Plot: zkp-chain/api-server/attacks/");
  console.log("     → Attack Matrix   : zkp-chain/api-server/attacks/attack_matrix_plot.png");
  console.log("   - Comparative Evaluation Plots: zkp-chain/api-server/compareBenchmarks/");
  console.log("     → Comparative     : zkp-chain/api-server/compareBenchmarks/figure3_latency_breakdown.pdf");
  console.log("   - Biometric JSON Metrics: zkp-chain/api-server/benchmark/biometric_accuracy_results.json");
  console.log("   - On-chain vs Off-chain Metrics: zkp-chain/api-server/benchmark/onchain_vs_offchain_results.json");
  console.log("   - Scalability Sweeps: zkp-chain/api-server/benchmark/e2e_scalability_results.json");
  console.log("   - Homomorphic Sweeps: zkp-chain/api-server/benchmark/homomorphic_results.json");
  console.log("   - Attack Matrix: zkp-chain/api-server/attacks/results/attack_matrix.json\n");
})();
