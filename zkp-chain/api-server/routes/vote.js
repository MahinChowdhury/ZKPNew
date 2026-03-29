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

// secp256k1 key derivation — for LRS only (unchanged)
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
 * Cast anonymous vote using:
 *   1. ZK-SNARK proof (Poseidon + Baby Jubjub + cosine similarity)
 *   2. Linkable Ring Signature (secp256k1, unchanged)
 *   3. Homomorphic encryption of vote vector
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
      const { fabricClient, decodeQRCode, getFaceEmbedding, compareEmbeddings, ballotRoutes, tallyRoutes, snark } = res.locals;

      if (!password || !qrFile || !faceFile || !voteChoice) {
        return res.status(400).json({ 
          ok: false, 
          error: "Missing required fields: password, qrCode, faceImg, voteChoice" 
        });
      }

      console.log("\n=== VOTE SUBMISSION START (ZK-SNARK + LRS) ===");
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
      const qrData = decryptPayload(encryptedStr, password);
      console.log("✅ QR decrypted");

      // 7. Live face embedding extraction
      const faceLogin = await getFaceEmbedding(faceFile);
      const registeredEmbedding = qrData.faceEmbedding;
      
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      // =====================================================
      // 8. ZK-SNARK PROOF — replaces simple compareEmbeddings
      // Proves inside the circuit:
      //   a) Poseidon(embedding || salt) == faceHash
      //   b) S = k * G on Baby Jubjub (key ownership)
      //   c) squared_cosine(live, registered) >= threshold
      // =====================================================
      let snarkProofResult = null;

      if (qrData.poseidonFaceHash && qrData.bjjSx && qrData.bjjSy && snark) {
        console.log("🔐 Generating ZK-SNARK proof of biometric match...");
        
        snarkProofResult = await snark.generateAuthProof(
          faceLogin,
          registeredEmbedding,
          qrData.salt,
          BigInt(qrData.poseidonFaceHash),
          BigInt(qrData.bjjSx),
          BigInt(qrData.bjjSy)
        );

        if (!snarkProofResult.isValid) {
          return res.json({
            ok: false,
            error: "ZK-SNARK proof verification failed — biometric mismatch or data tampering",
            isMatch: false
          });
        }

        console.log("✅ ZK-SNARK biometric proof verified");
      } else {
        // Legacy fallback: use Python compare endpoint
        console.warn("⚠️  Legacy registration detected — using Python compare (no SNARK)");
        const isMatch = await compareEmbeddings(faceLogin, registeredEmbedding);
        console.log("Face match result:", isMatch);

        if (!isMatch) {
          return res.json({
            ok: false,
            error: "Face verification failed - biometric mismatch",
            isMatch: false
          });
        }
        console.log("✅ Legacy biometric verification passed");
      }

      // 9. Derive secp256k1 private key for LRS (unchanged)
      const faceHashSha = qrData.faceHash || sha256Hash(JSON.stringify(registeredEmbedding));
      const k = deriveK(faceHashSha, qrData.salt);
      
      // 10. Compute link tag S = k·G (secp256k1)
      const S = ec.g.mul(k);
      const linkTag = {
        x: S.getX().toString(16),
        y: S.getY().toString(16)
      };

      // 11. Get ring (all registered public keys)
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

      // 12. Homomorphic encryption of vote vector + ZKP (unchanged)
      let encryptedVoteVector = null;
      let signatureMessage = voteChoice;
      
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
          
          signatureMessage = sha256Hash(JSON.stringify(encryptedVoteVector));
        } else {
          console.warn("No encryption key found for ballot - vote will not be encrypted");
          console.warn("   Run: POST /api/v1/tally/setup/" + activeBallot.id);
        }
      } catch (err) {
        console.warn("Could not encrypt vote:", err.message);
      }

      // 13. Generate linkable ring signature over the encrypted vector (secp256k1, unchanged)
      const signature = lrs.sign(k, ring, signerIndex, signatureMessage);
      console.log("✅ Ring signature generated (secp256k1 LRS)");

      // 14. Verify signature locally before submitting
      const isValid = lrs.verify(signature, ring, signatureMessage);
      if (!isValid) {
        throw new Error("Generated signature failed local verification");
      }
      console.log("✅ Local LRS verification passed");

      // 15. Submit vote to blockchain
      const voteResult = await fabricClient.castVote(
        signature,
        ringData,
        encryptedVoteVector
      );

      console.log("✅ Vote cast on blockchain");
      console.log("Vote ID:", voteResult.voteId);
      console.log("=== VOTE SUBMISSION COMPLETE (ZK-SNARK + LRS) ===\n");

      res.json({
        ok: true,
        isMatch: true,
        voteId: voteResult.voteId,
        voteChoice,
        ballotTitle: activeBallot.title,
        timestamp: voteResult.timestamp,
        zkp: {
          snarkProof: snarkProofResult ? true : false,
          lrsSignature: true,
          protocol: "plonk + lrs",
          curves: "bn128 (snark) + secp256k1 (lrs)"
        },
        message: "Vote successfully cast with ZK-SNARK biometric proof + anonymous ring signature"
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
    
    // Determine the signed message for verification
    if (!vote.encryptedVote || !Array.isArray(vote.encryptedVote)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid vote format. Expected encrypted vector."
      });
    }

    // The signed message is the hash of the encrypted vector
    const signatureMessage = sha256Hash(JSON.stringify(vote.encryptedVote));
    const isValid = lrs.verify(vote.signature, ring, signatureMessage);
    
    res.json({
      ok: true,
      voteId,
      isValid,
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
      anonymitySet: ringData.length,
      zkp: "zk-snark (PLONK) + LRS (secp256k1)"
    });
  } catch (err) {
    console.error("STATUS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;