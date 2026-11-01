// ============================
// Vote Routes
// Architecture: ZK-SNARK + Merkle Tree + Nullifier
// Supports: Face AND Iris biometric modes (independent)
//
// The gateway is a relay: the voter's client (frontend/src/crypto/
// voterClient.js) builds the proof and the encrypted ballot. The gateway
// never receives the credential, password, biometric sample or vote
// choice, and every check that matters is enforced by the chaincode.
// ============================

const express = require("express");

const router = express.Router();

/**
 * POST /api/v1/vote
 * Relay a client-built vote transaction to the ledger.
 *
 * Body (JSON):
 * - ballotId, biometricMode ("face" | "iris")
 * - proof, publicSignals  — Groth16 proof from the client
 * - nullifier             — Poseidon(sk, electionId), also publicSignals[2]
 * - encryptedBallot       — { ciphertexts: [{c1, c2, validityProof}], sumProof }
 */
router.post("/", async (req, res) => {
  try {
    const { ballotId, proof, publicSignals, nullifier, encryptedBallot } = req.body || {};
    const mode = req.body?.biometricMode || "face";
    const { fabricClient, ballotRoutes } = res.locals;

    if (!ballotId || !proof || !publicSignals || !nullifier || !encryptedBallot) {
      return res.status(400).json({
        ok: false,
        error: "Missing required fields: ballotId, proof, publicSignals, nullifier, encryptedBallot",
      });
    }
    if (mode !== "face" && mode !== "iris") {
      return res.status(400).json({ ok: false, error: `Invalid biometricMode: ${mode}` });
    }

    // Early rejection only: the chaincode enforces open/closed itself
    const activeBallot = ballotRoutes.getBallotById(ballotId);
    if (!activeBallot) {
      return res.status(404).json({ ok: false, error: `Ballot not found: ${ballotId}` });
    }
    if (activeBallot.status !== "active") {
      return res.status(400).json({ ok: false, error: `Ballot is ${activeBallot.status}. Voting is not allowed.` });
    }
    if (activeBallot.startTime && new Date(activeBallot.startTime) > new Date()) {
      return res.status(400).json({ ok: false, error: "Ballot has not started yet" });
    }
    if (activeBallot.endTime && new Date(activeBallot.endTime) < new Date()) {
      return res.status(400).json({ ok: false, error: "Ballot has expired" });
    }

    // The chaincode verifies the Groth16 proof, Merkle root, election and
    // ciphertext bindings, every Σ-OR / sum proof, and nullifier freshness.
    const voteResult = await fabricClient.castVote(
      proof, publicSignals, String(nullifier), encryptedBallot, ballotId, mode
    );

    console.log(`✅ Vote relayed for ballot ${ballotId} (${mode}) → ${voteResult.voteId}`);
    res.json({
      ok: true,
      voteId: voteResult.voteId,
      ballotId,
      biometricMode: mode,
      timestamp: voteResult.timestamp,
      onChainVerified: true,
      nullifier: String(nullifier),
    });
  } catch (err) {
    const msg = err.message || String(err);
    if (/already voted|Double voting/i.test(msg)) {
      return res.status(403).json({ ok: false, error: "Double voting detected - you have already cast a vote", code: "DOUBLE_VOTE" });
    }
    console.error("VOTE RELAY ERROR:", msg);
    res.status(400).json({ ok: false, error: msg });
  }
});

/**
 * GET /api/v1/vote/nullifier/:nullifier
 * Has this nullifier been used? Lets the client fail fast before proving.
 */
router.get("/nullifier/:nullifier", async (req, res) => {
  try {
    const used = await res.locals.fabricClient.hasVoted(req.params.nullifier);
    res.json({ ok: true, used });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/vote/results
 * Get voting results (public)
 * Query: ?ballotId=xyz
 */
router.get("/results", async (req, res) => {
  try {
    const { fabricClient } = res.locals;
    const ballotId = req.query.ballotId || '';
    
    const results = await fabricClient.getVoteResults(ballotId);
    
    res.json({
      ok: true,
      totalVotes: results.totalVotes,
      results: results.tallies,
      voterCount: results.voterCount
    });
  } catch (err) {
    console.error("GET RESULTS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/vote/verify/:voteId
 * Verify a specific vote's SNARK proof (public audit)
 * Tries face verification key first, then iris if that fails.
 */
router.get("/verify/:voteId", async (req, res) => {
  try {
    const { voteId } = req.params;
    const { fabricClient, snark, irisSnark } = res.locals;
    
    const vote = await fabricClient.getVote(voteId);
    
    // Try face verification first, then iris
    let isValid = false;
    let verifiedWith = "unknown";

    try {
      isValid = await snark.verifyProof(vote.proof, vote.publicSignals);
      if (isValid) verifiedWith = "face";
    } catch (e) {
      // Face verification failed, try iris
    }

    if (!isValid) {
      try {
        isValid = await irisSnark.verifyIrisProof(vote.proof, vote.publicSignals);
        if (isValid) verifiedWith = "iris";
      } catch (e) {
        // Iris verification also failed
      }
    }
    
    res.json({
      ok: true,
      voteId,
      isValid,
      verifiedWith,
      nullifier: vote.nullifier,
      timestamp: vote.timestamp
    });
  } catch (err) {
    console.error("VERIFY VOTE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/vote/status
 * Get voting system status
 * Query: ?ballotId=xyz
 */
router.get("/status", async (req, res) => {
  try {
    const { fabricClient } = res.locals;
    const ballotId = req.query.ballotId || '';
    
    const faceCommitments = await fabricClient.getCommitments();
    const irisCommitments = await fabricClient.getIrisCommitments();
    const results = await fabricClient.getVoteResults(ballotId);
    
    res.json({
      ok: true,
      registeredVoters: {
        face: faceCommitments.length,
        iris: irisCommitments.length,
        total: faceCommitments.length + irisCommitments.length,
      },
      totalVotes: results.totalVotes,
      votingActive: true,
      anonymitySet: {
        face: faceCommitments.length,
        iris: irisCommitments.length,
      },
      zkp: "zk-snark (Groth16) + Merkle Tree + Nullifier",
      biometricModes: ["face (cosine similarity)", "iris (hamming distance)"],
    });
  } catch (err) {
    console.error("STATUS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;