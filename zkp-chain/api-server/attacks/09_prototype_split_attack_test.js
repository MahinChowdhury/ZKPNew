/**
 * ═══════════════════════════════════════════════════════════════════
 *  Category 9 — Prototype Split & Zeroed Proof Bypass Attack Test
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Demonstrates the "Prototype Split" vulnerability (RQ3) where out-of-band
 *  validation could allow compromised clients to submit zeroed/forged proofs.
 *  It then proves how our integrated on-chain Groth16 contract verification
 *  completely mitigates this vulnerability.
 *
 *  OFFLINE crypto & smart contract logic tests — no live network needed.
 *
 *  Run: node attacks/09_prototype_split_attack_test.js
 */

"use strict";

const {
  nowMs, suppress, suppressAsync,
  printHeader, printSubHeader, printResult, printTable,
  saveResults
} = require("./utils");
const snark = require("../crypto/snark");
const homomorphic = require("../crypto/homomorphic");

// Simulates the legacy "split validation" contract where proof verification was only client-side
class LegacySplitContract {
  constructor() {
    this.ledger = [];
  }

  // Accepts whatever is submitted without verifying the ZK-SNARK on-chain
  async castVote(nullifier, encryptedVoteJSON, proofJSON, publicSignalsJSON) {
    // Legacy contract only checked simple parameters, omitting snarkjs.groth16.verify()
    if (!nullifier || !encryptedVoteJSON) {
      throw new Error("Missing parameters");
    }
    
    // Accept and commit directly to ledger
    this.ledger.push({
      nullifier,
      encryptedVote: encryptedVoteJSON,
      proof: proofJSON,
      publicSignals: publicSignalsJSON,
      status: "COMMITTED"
    });
    return { status: "SUCCESS", txId: "tx_" + Math.random().toString(36).slice(2, 9) };
  }
}

// Simulates the hardened, integrated on-chain verification contract (matches identityContract.js)
class HardenedIntegratedContract {
  constructor(verificationKey) {
    this.ledger = [];
    this.vkey = verificationKey;
  }

  // Hardened on-chain verification helper
  async verifyZkProof(proof, publicSignals) {
    try {
      // Direct cryptographic verification inside the smart contract execution environment
      return await snark.verifyProof(proof, publicSignals);
    } catch (e) {
      return false;
    }
  }

  async castVote(nullifier, encryptedVoteJSON, proofJSON, publicSignalsJSON) {
    if (!nullifier || !encryptedVoteJSON || !proofJSON || !publicSignalsJSON) {
      throw new Error("Missing parameters");
    }

    const proof = JSON.parse(proofJSON);
    const publicSignals = JSON.parse(publicSignalsJSON);

    // STEP 1: Mandatory on-chain Groth16 cryptographic proof verification
    const isProofValid = await this.verifyZkProof(proof, publicSignals);
    if (!isProofValid) {
      throw new Error("ZK-SNARK proof verification FAILED on-chain — transaction reverted!");
    }

    // STEP 2: Nullifier embedded in proof must match the transaction parameter
    if (publicSignals[3] !== nullifier) {
      throw new Error("Nullifier mismatch — transaction reverted!");
    }

    // Commit to ledger
    this.ledger.push({
      nullifier,
      encryptedVote: encryptedVoteJSON,
      proof: proofJSON,
      publicSignals: publicSignalsJSON,
      status: "COMMITTED"
    });
    return { status: "SUCCESS", txId: "tx_" + Math.random().toString(36).slice(2, 9) };
  }
}

async function run() {
  printHeader("Category 9 — Prototype Split & Zeroed Proof Bypass Attack (RQ3)");

  const results = {
    category: "Prototype Split & Zeroed Proof Bypass",
    timestamp: new Date().toISOString(),
    tests: {}
  };

  // 1. Generate a malicious zeroed proof payload (all components are blank/zero)
  const maliciousZeroedProof = {
    pi_a: ["0", "0", "0"],
    pi_b: [
      ["0", "0"],
      ["0", "0"],
      ["0", "0"]
    ],
    pi_c: ["0", "0", "0"],
    protocol: "groth16",
    curve: "bn128"
  };

  // Public signals: [output_valid=1, face_hash, merkle_root, nullifier, election_id]
  const mockPublicSignals = [
    "1", // Claim biometric similarity check passed (malicious public signal)
    "999999999", // Mock biometric hash
    "888888888", // Mock Merkle root
    "777777777", // Nullifier
    "12345"      // Election ID
  ];

  const nullifier = "777777777";
  const encryptedVote = JSON.stringify({ cipher: "dummy" });

  const proofJSON = JSON.stringify(maliciousZeroedProof);
  const publicSignalsJSON = JSON.stringify(mockPublicSignals);

  // Load actual verification key to ensure contract uses realistic key configurations
  const vkey = snark.getVerificationKey();

  // ─── 9.1  Attack against Legacy Split Validation Contract ─────────────────────
  printSubHeader("9.1  Bypass Attempt on Legacy Split Validation Contract (Out-of-band only)");
  
  const legacyContract = new LegacySplitContract();
  let legacyAccepted = false;
  let legacyTx = null;

  try {
    const res = await legacyContract.castVote(nullifier, encryptedVote, proofJSON, publicSignalsJSON);
    legacyAccepted = (res.status === "SUCCESS");
    legacyTx = res.txId;
  } catch (e) {
    legacyAccepted = false;
  }

  results.tests["9.1_legacy_split_bypass"] = {
    payload: "zeroed_proof",
    accepted: legacyAccepted,
    txId: legacyTx,
    pass: legacyAccepted === true // Pass means we successfully showed the vulnerability exists historically
  };

  printResult("Zeroed proof accepted by Legacy Split Contract", legacyAccepted, legacyAccepted);
  if (legacyAccepted) {
    console.log(`  ⚠️  VULNERABLE: Ledger committed fake vote in tx ${legacyTx} without verification!`);
  }

  // ─── 9.2  Attack against Hardened Integrated On-Chain Validation Contract ──────
  printSubHeader("9.2  Verification Enforcement by Hardened On-Chain Contract (Integrated)");

  const hardenedContract = new HardenedIntegratedContract(vkey);
  let hardenedAccepted = false;
  let hardenedError = null;

  try {
    await hardenedContract.castVote(nullifier, encryptedVote, proofJSON, publicSignalsJSON);
    hardenedAccepted = true;
  } catch (e) {
    hardenedAccepted = false;
    hardenedError = e.message;
  }

  results.tests["9.2_hardened_onchain_rejection"] = {
    payload: "zeroed_proof",
    accepted: hardenedAccepted,
    error: hardenedError,
    pass: (hardenedAccepted === false) && (hardenedError && hardenedError.includes("reverted"))
  };

  printResult("Zeroed proof rejected by Hardened Contract", !hardenedAccepted, !hardenedAccepted);
  if (!hardenedAccepted) {
    console.log(`  🛡️  SECURE: On-chain smart contract intercepted fake proof: "${hardenedError}"`);
  }

  // ─── Summary ──────────────────────────────────────────────────
  printSubHeader("Summary");
  const allTests = Object.values(results.tests);
  const passed = allTests.filter(t => t.pass).length;

  printTable([
    ["Test Case", "Legacy Split Contract", "Hardened Integrated Contract", "Result"],
    ["9.1 Legacy Split Bypass", "ACCEPTED (Vulnerable)", "N/A", results.tests["9.1_legacy_split_bypass"].pass ? "PASS" : "FAIL"],
    ["9.2 Hardened Rejection", "N/A", "REJECTED (Secure)", results.tests["9.2_hardened_onchain_rejection"].pass ? "PASS" : "FAIL"]
  ]);

  console.log(`\n  Overall: ${passed}/${allTests.length} tests completed successfully`);

  saveResults("09_prototype_split_results.json", results);
  return results;
}

if (require.main === module) {
  run().catch(console.error);
}

module.exports = { run };
