// ============================
// Vote Routes
// ============================

const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const EC = require("elliptic").ec;
const BN = require("bn.js");
const lrs = require("../crypto/lrs");
const homomorphic = require("../crypto/homomorphic");

const ec = new EC("secp256k1");
const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

function sha256Hash(data) {
  if (data === undefined || data === null) {
    throw new Error("sha256Hash() received undefined data");
  }
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}

function deriveK(faceHash, salt) {
  const hash = sha256Hash(faceHash + salt);
  let k = new BN(hash, 16).umod(ec.curve.n);
  if (k.isZero()) k = k.iaddn(1);
  return k;
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
 * Cast anonymous vote using linkable ring signature
 * 
 * Body:
 * - qrCode: encrypted QR with user credentials
 * - faceImg: live face photo for biometric verification
 * - password: to decrypt QR
 * - voteChoice: the vote (must match an option in active ballot)
 */
router.post(
  "/",
  upload.fields([{ name: "qrCode" }, { name: "faceImg" }]),
  async (req, res) => {
    try {
      const { password, voteChoice } = req.body;
      const qrFile = req.files.qrCode?.[0];
      const faceFile = req.files.faceImg?.[0];
      
      // Get external dependencies from res.locals (set by server.js)
      const { fabricClient, decodeQRCode, getFaceEmbedding, compareEmbeddings, ballotRoutes, tallyRoutes } = res.locals;

      if (!password || !qrFile || !faceFile || !voteChoice) {
        return res.status(400).json({ 
          ok: false, 
          error: "Missing required fields: password, qrCode, faceImg, voteChoice" 
        });
      }

      console.log("\n=== VOTE SUBMISSION START ===");
      console.log("Vote choice:", voteChoice);

      // 1. Check if there's an active ballot
      const activeBallot = ballotRoutes.getActiveBallot();
      if (!activeBallot) {
        return res.status(400).json({
          ok: false,
          error: "No active ballot available"
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
      
      // Parse and decrypt
      const encrypted = JSON.parse(encryptedStr);
      const key = crypto.createHash("sha256").update(password).digest();
      const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        key,
        Buffer.from(encrypted.iv, "base64")
      );
      
      let decrypted = decipher.update(encrypted.data, "base64", "utf8");
      decrypted += decipher.final("utf8");
      const qrData = JSON.parse(decrypted);
      console.log("✅ QR decrypted");

      // 7. Live face verification
      const faceLogin = await getFaceEmbedding(faceFile);
      const registeredEmbedding = qrData.faceEmbedding;
      
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      const isMatch = await compareEmbeddings(faceLogin, registeredEmbedding);
      console.log("Face match result:", isMatch);

      if (!isMatch) {
        return res.json({
          ok: false,
          error: "Face verification failed - biometric mismatch",
          isMatch: false
        });
      }

      console.log("✅ Biometric verification passed");

      // 8. Derive private key k from biometric
      const k = deriveK(qrData.faceHash, qrData.salt);
      
      // 9. Compute link tag S = k·G
      const S = ec.g.mul(k);
      const linkTag = {
        x: S.getX().toString(16),
        y: S.getY().toString(16)
      };

      // 10. Get ring (all registered public keys)
      const ringData = await fabricClient.getRing();
      
      if (!ringData || ringData.length === 0) {
        throw new Error("No registered users in the ring");
      }

      console.log(`Ring size: ${ringData.length} members`);

      // Reconstruct ring as elliptic curve points
      const ring = ringData.map(pk => 
        ec.curve.point(new BN(pk.x, 16), new BN(pk.y, 16))
      );

      // Find signer's index in ring
      let signerIndex = -1;
      for (let i = 0; i < ringData.length; i++) {
        if (ringData[i].x === linkTag.x && ringData[i].y === linkTag.y) {
          signerIndex = i;
          break;
        }
      }

      if (signerIndex === -1) {
        throw new Error("Signer's public key not found in ring - user not registered");
      }

      console.log(`Signer index in ring: ${signerIndex}`);

      // 11. Generate linkable ring signature
      const signature = lrs.sign(k, ring, signerIndex, voteChoice);
      console.log("✅ Ring signature generated");

      // 12. Verify signature locally before submitting
      const isValid = lrs.verify(signature, ring, voteChoice);
      if (!isValid) {
        throw new Error("Generated signature failed local verification");
      }
      console.log("✅ Local signature verification passed");

      // 13. Homomorphic encryption of vote + vote validity ZKP
      // Get ballot's public key
      let encryptedVote = null;
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
          
          // Encrypt vote value (1 for this choice, 0 for others)
          const voteValue = 1;
          const cipher = homomorphic.encrypt(publicKey, voteValue);
          
          // Generate Disjunctive Chaum-Pedersen ZKP proving vote is 0 or 1
          const validityProof = homomorphic.proveValidVote(publicKey, cipher, voteValue, cipher.r);
          
          // Verify proof locally before submission
          const proofValid = homomorphic.verifyValidVote(publicKey, cipher, validityProof);
          if (!proofValid) {
            throw new Error("Vote validity ZKP failed local verification");
          }
          console.log("Vote validity ZKP generated and verified locally");

          encryptedVote = homomorphic.serializeCiphertext(cipher);
          // Attach the validity proof to the encrypted vote
          encryptedVote.validityProof = validityProof;
          
          console.log("Vote encrypted homomorphically");
          console.log(`   c1: ${encryptedVote.c1.x.slice(0, 16)}...`);
          console.log(`   c2: ${encryptedVote.c2.x.slice(0, 16)}...`);
        } else {
          console.warn("No encryption key found for ballot - vote will not be encrypted");
          console.warn("   Run: POST /api/v1/tally/setup/" + activeBallot.id);
        }
      } catch (err) {
        console.warn("Could not encrypt vote:", err.message);
        console.warn("   Make sure encryption is setup: POST /api/v1/tally/setup/" + activeBallot.id);
      }
      // 14. Compute choice hash for on-chain storage (privacy preserving)
      const voteChoiceHash = sha256Hash(voteChoice);

      // 15. Submit vote to blockchain (only hash goes on-chain, not plaintext)
      const voteResult = await fabricClient.castVote(
        voteChoiceHash,
        signature,
        ringData,
        encryptedVote
      );

      console.log("✅ Vote cast on blockchain");
      console.log("Vote ID:", voteResult.voteId);
      console.log("=== VOTE SUBMISSION COMPLETE ===\n");

      res.json({
        ok: true,
        isMatch: true,
        voteId: voteResult.voteId,
        voteChoice,  // API response shows the original choice (client-side only)
        ballotTitle: activeBallot.title,
        timestamp: voteResult.timestamp,
        message: "Vote successfully cast anonymously"
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
 */
router.get("/results", async (req, res) => {
  try {
    const { fabricClient } = res.locals;
    
    const results = await fabricClient.getVoteResults();
    
    res.json({
      ok: true,
      totalVotes: results.totalVotes,
      results: results.tallies,
      ringSize: results.ringSize
    });
  } catch (err) {
    console.error("GET RESULTS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/vote/verify/:voteId
 * Verify a specific vote's signature (public audit)
 */
router.get("/verify/:voteId", async (req, res) => {
  try {
    const { voteId } = req.params;
    const { fabricClient } = res.locals;
    
    const vote = await fabricClient.getVote(voteId);
    
    // Reconstruct ring
    const ring = vote.ring.map(pk => 
      ec.curve.point(new BN(pk.x, 16), new BN(pk.y, 16))
    );
    
    // Verify signature — LRS was signed with plaintext voteChoice,
    // but on-chain only the hash is stored. We need to find the matching
    // plaintext from ballot options to verify the signature.
    const ballot = require('./ballot').getActiveBallot && require('./ballot').getActiveBallot();
    let matchedChoice = null;
    
    // Try to match the hash to a known ballot option
    if (ballot && ballot.options) {
      for (const option of ballot.options) {
        if (sha256Hash(option.name) === (vote.voteChoiceHash || vote.voteChoice)) {
          matchedChoice = option.name;
          break;
        }
      }
    }
    
    // Fallback: if vote still has legacy plaintext voteChoice
    if (!matchedChoice && vote.voteChoice) {
      matchedChoice = vote.voteChoice;
    }
    
    const isValid = matchedChoice ? lrs.verify(vote.signature, ring, matchedChoice) : false;
    
    res.json({
      ok: true,
      voteId,
      isValid,
      voteChoiceHash: vote.voteChoiceHash || sha256Hash(vote.voteChoice),
      timestamp: vote.timestamp,
      ringSize: vote.ring.length
    });
  } catch (err) {
    console.error("VERIFY VOTE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/vote/status
 * Get voting system status
 */
router.get("/status", async (req, res) => {
  try {
    const { fabricClient } = res.locals;
    
    const ringData = await fabricClient.getRing();
    const results = await fabricClient.getVoteResults();
    
    res.json({
      ok: true,
      registeredVoters: ringData.length,
      totalVotes: results.totalVotes,
      votingActive: true,
      anonymitySet: ringData.length
    });
  } catch (err) {
    console.error("STATUS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;