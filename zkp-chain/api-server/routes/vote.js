// ============================
// Vote Routes
// Architecture: ZK-SNARK + Merkle Tree + Nullifier
// Supports: Face AND Iris biometric modes (independent)
// ============================

const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const homomorphic = require("../crypto/homomorphic");

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

function sha256Hash(data) {
  if (data === undefined || data === null) {
    throw new Error("sha256Hash() received undefined data");
  }
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}

function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
}

function decryptPayload(encryptedPayload, password) {
  const parsed = JSON.parse(encryptedPayload);
  const { iv, data } = parsed;
  const pbkdfSalt = parsed.salt
    ? Buffer.from(parsed.salt, "base64")
    : null;
  const key = pbkdfSalt
    ? deriveKeyFromPassword(password, pbkdfSalt)
    : crypto.createHash("sha256").update(password).digest(); // legacy fallback
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    key,
    Buffer.from(iv, "base64")
  );

  let decrypted = decipher.update(data, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

/**
 * POST /api/v1/vote
 * Cast anonymous vote using:
 *   1. ZK-SNARK proof (Face: cosine similarity | Iris: Hamming distance)
 *      + Merkle Tree membership + Nullifier
 *   2. Homomorphic encryption of vote vector
 * 
 * Body:
 * - ballotId: ID of the ballot to vote on (required)
 * - qrCode: encrypted QR with user credentials
 * - faceImg: live face photo (for face mode)
 * - irisImg: live iris photo (for iris mode)
 * - password: to decrypt QR
 * - voteChoice: the vote (must match an option in the specified ballot)
 * - biometricMode: "face" (default) or "iris"
 */
router.post(
  "/",
  upload.fields([{ name: "qrCode" }, { name: "faceImg" }, { name: "irisImg" }]),
  async (req, res) => {
    try {
      const { password, voteChoice, biometricMode, ballotId } = req.body;
      const mode = biometricMode || "face";

      const qrFile = req.files.qrCode?.[0];
      const faceFile = req.files.faceImg?.[0];
      const irisFile = req.files.irisImg?.[0];
      
      // Get external dependencies from res.locals (set by server.js)
      const {
        fabricClient, decodeQRCode, getFaceEmbedding, getIrisCode,
        ballotRoutes, tallyRoutes, snark, irisSnark, credentialStore,
      } = res.locals;

      if (!password || !qrFile || !voteChoice || !ballotId) {
        return res.status(400).json({ 
          ok: false, 
          error: "Missing required fields: ballotId, password, qrCode, voteChoice" 
        });
      }

      if (mode === "face" && !faceFile) {
        return res.status(400).json({ ok: false, error: "Missing faceImg for face biometric mode" });
      }

      if (mode === "iris" && !irisFile) {
        return res.status(400).json({ ok: false, error: "Missing irisImg for iris biometric mode" });
      }

      console.log(`\n=== VOTE SUBMISSION START (${mode.toUpperCase()} — ZK-SNARK + Merkle + Nullifier) ===`);
      console.log("Ballot ID:", ballotId);
      console.log("Vote choice:", voteChoice);
      console.log("Biometric mode:", mode);

      // 1. Look up the ballot by ID
      const activeBallot = ballotRoutes.getBallotById(ballotId);
      if (!activeBallot) {
        return res.status(404).json({
          ok: false,
          error: `Ballot not found: ${ballotId}`
        });
      }

      // 2. Validate ballot status
      if (activeBallot.status !== "active") {
        return res.status(400).json({
          ok: false,
          error: `Ballot is ${activeBallot.status}. Voting is not allowed.`
        });
      }

      // 3. Check if ballot has started
      if (activeBallot.startTime && new Date(activeBallot.startTime) > new Date()) {
        return res.status(400).json({
          ok: false,
          error: "Ballot has not started yet"
        });
      }

      // 4. Check if ballot has expired
      if (activeBallot.endTime && new Date(activeBallot.endTime) < new Date()) {
        return res.status(400).json({
          ok: false,
          error: "Ballot has expired"
        });
      }

      // 5. Validate vote choice against ballot options
      const validOptions = activeBallot.options.map(o => o.name);
      if (!validOptions.includes(voteChoice)) {
        return res.status(400).json({
          ok: false,
          error: `Invalid vote choice. Must be one of: ${validOptions.join(", ")}`,
          validOptions
        });
      }

      console.log(`✅ Ballot validation passed: "${activeBallot.title}"`);

      // 6. Decode and decrypt QR code
      const encryptedStr = await decodeQRCode(qrFile);
      console.log("✅ QR decoded");
      
      const qrData = decryptPayload(encryptedStr, password);
      console.log("✅ QR decrypted");

      // Verify QR biometric mode matches request
      const qrMode = qrData.biometricMode || "face";
      if (qrMode !== mode) {
        return res.status(400).json({
          ok: false,
          error: `QR code was registered with "${qrMode}" biometric but vote mode is "${mode}". Please use the correct mode.`,
        });
      }

      // 7. Election ID from ballot
      const electionIdHash = sha256Hash(activeBallot.id);
      const electionId = BigInt("0x" + electionIdHash.slice(0, 32));

      let snarkProofResult;
      let nullifier;

      if (mode === "face") {
        // =====================================================
        // FACE VOTE PIPELINE
        // =====================================================

        // Get live face embedding
        const faceLogin = await getFaceEmbedding(faceFile);
        const registeredEmbedding = qrData.faceEmbedding;

        if (!registeredEmbedding) {
          throw new Error("No face embedding found in QR code");
        }

        // Load face SNARK credentials
        const snarkCreds = credentialStore.loadCredentials(qrData.nidHash, password);
        console.log("✅ Face SNARK credentials loaded");

        // Get face commitments for Merkle tree
        const commitments = await fabricClient.getCommitments();
        const commitmentsBigInt = commitments.map((c) => BigInt(c));
        console.log(`✅ Fetched ${commitments.length} face commitments for Merkle tree`);

        // Compute nullifier for double-vote check
        nullifier = await snark.computeNullifier(
          BigInt(snarkCreds.secretKey),
          electionId
        );

        // Early double-vote check
        const alreadyVoted = await fabricClient.hasVoted(nullifier.toString());
        if (alreadyVoted) {
          return res.status(403).json({
            ok: false,
            error: "Double voting detected - you have already cast a vote in this election",
            code: "DOUBLE_VOTE"
          });
        }

        // Generate face ZK-SNARK proof
        console.log("🔐 Generating face ZK-SNARK proof...");
        snarkProofResult = await snark.generateAuthProof(
          faceLogin,
          registeredEmbedding,
          qrData.salt,
          BigInt(snarkCreds.poseidonFaceHash),
          BigInt(snarkCreds.secretKey),
          commitmentsBigInt,
          electionId
        );

        if (!snarkProofResult.isValid) {
          return res.json({
            ok: false,
            error: "Face ZK-SNARK proof verification failed — biometric mismatch or data tampering",
            isMatch: false
          });
        }

        console.log("✅ Face ZK-SNARK proof verified (biometric + Merkle membership + nullifier)");

      } else if (mode === "iris") {
        // =====================================================
        // IRIS VOTE PIPELINE
        // =====================================================

        // Get live iris code from Python
        const liveIrisResult = await getIrisCode(irisFile);
        console.log("✅ Live iris code extracted (quality:", liveIrisResult.quality, ")");

        // Load iris SNARK credentials (with _iris suffix)
        const irisCreds = credentialStore.loadCredentials(qrData.nidHash, password, "_iris");
        console.log("✅ Iris SNARK credentials loaded");

        const registeredIrisCode256 = irisCreds.irisCode256;
        if (!registeredIrisCode256) {
          throw new Error("No iris code found in credential store");
        }

        // Get iris commitments for independent Merkle tree
        const irisCommitments = await fabricClient.getIrisCommitments();
        const irisCommitmentsBigInt = irisCommitments.map((c) => BigInt(c));
        console.log(`✅ Fetched ${irisCommitments.length} iris commitments for Merkle tree`);

        // Compute nullifier for double-vote check
        nullifier = await irisSnark.computeIrisNullifier(
          BigInt(irisCreds.secretKey),
          electionId
        );

        // Early double-vote check
        const alreadyVoted = await fabricClient.hasVoted(nullifier.toString());
        if (alreadyVoted) {
          return res.status(403).json({
            ok: false,
            error: "Double voting detected - you have already cast a vote in this election",
            code: "DOUBLE_VOTE"
          });
        }

        // Generate iris ZK-SNARK proof
        console.log("🔐 Generating iris ZK-SNARK proof (Hamming distance)...");
        snarkProofResult = await irisSnark.generateIrisAuthProof(
          liveIrisResult.irisCode,
          liveIrisResult.noiseMask,
          registeredIrisCode256,
          qrData.salt,
          BigInt(irisCreds.poseidonIrisHash),
          BigInt(irisCreds.secretKey),
          irisCommitmentsBigInt,
          electionId
        );

        if (!snarkProofResult.isValid) {
          return res.json({
            ok: false,
            error: "Iris ZK-SNARK proof verification failed — iris biometric mismatch or data tampering",
            isMatch: false
          });
        }

        console.log("✅ Iris ZK-SNARK proof verified (Hamming distance + Merkle membership + nullifier)");

      } else {
        return res.status(400).json({ ok: false, error: `Invalid biometricMode: ${mode}` });
      }

      // =====================================================
      // COMMON: Homomorphic encryption + blockchain submission
      // (Same for both face and iris modes)
      // =====================================================

      const EC = require("elliptic").ec;
      const BN = require("bn.js");
      const ec = new EC("secp256k1");

      let encryptedVoteVector = null;
      
      try {
        const axios = require('axios');
        const pkResponse = await axios.get(
          `http://localhost:${process.env.PORT || 3000}/api/v1/tally/publickey/${activeBallot.id}`
        );
        
        if (pkResponse.data && pkResponse.data.ok && pkResponse.data.publicKey) {
          const publicKey = ec.curve.point(
            new BN(pkResponse.data.publicKey.x, 16),
            new BN(pkResponse.data.publicKey.y, 16)
          );
          
          encryptedVoteVector = activeBallot.options.map(option => {
            const voteValue = (option.name === voteChoice) ? 1 : 0;
            const cipher = homomorphic.encrypt(publicKey, voteValue);
            const validityProof = homomorphic.proveValidVote(publicKey, cipher, voteValue, cipher.r);
            
            const proofValid = homomorphic.verifyValidVote(publicKey, cipher, validityProof);
            if (!proofValid) {
              throw new Error(`Vote validity ZKP failed local verification for option ${option.name}`);
            }
            
            const serialized = homomorphic.serializeCiphertext(cipher);
            serialized.validityProof = validityProof;
            return serialized;
          });
          
          console.log(`✅ Vote encrypted as vector of size ${encryptedVoteVector.length}`);
        } else {
          console.warn("No encryption key found for ballot - vote will not be encrypted");
          console.warn("   Run: POST /api/v1/tally/setup/" + activeBallot.id);
        }
      } catch (err) {
        console.warn("Could not encrypt vote:", err.message);
      }

      // Submit vote to blockchain with SNARK proof + nullifier
      const voteResult = await fabricClient.castVote(
        snarkProofResult.proof,
        snarkProofResult.publicSignals,
        nullifier.toString(),
        encryptedVoteVector,
        ballotId
      );

      console.log("✅ Vote cast on blockchain");
      console.log("Vote ID:", voteResult.voteId);
      console.log(`=== VOTE SUBMISSION COMPLETE (${mode.toUpperCase()} — ZK-SNARK + Merkle + Nullifier) ===\n`);

      res.json({
        ok: true,
        isMatch: true,
        voteId: voteResult.voteId,
        voteChoice,
        ballotId: activeBallot.id,
        biometricMode: mode,
        ballotTitle: activeBallot.title,
        timestamp: voteResult.timestamp,
        zkp: {
          snarkProof: true,
          merkleProof: true,
          nullifier: nullifier.toString().slice(0, 20) + "...",
          protocol: mode === "face"
            ? "groth16 + merkle + nullifier (cosine similarity)"
            : "groth16 + merkle + nullifier (hamming distance)",
          curve: "bn128",
        },
        message: `Vote successfully cast with ${mode.toUpperCase()} ZK-SNARK biometric proof + Merkle anonymous membership + nullifier anti-replay`,
      });

    } catch (err) {
      console.error("VOTE ERROR:", err);
      
      // Check for double-voting error
      if (err.message && err.message.includes("already voted")) {
        return res.status(403).json({ 
          ok: false, 
          error: "Double voting detected - you have already cast a vote",
          code: "DOUBLE_VOTE"
        });
      }
      
      res.status(500).json({ ok: false, error: err.message });
    }
  }
);

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