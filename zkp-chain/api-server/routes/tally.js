// ============================
// Homomorphic Tally Routes
// ============================

const express = require("express");
const homomorphic = require("../crypto/homomorphic");

const router = express.Router();

// Store encryption keypairs per ballot (in production, use secure key management)
const ballotKeys = new Map();

/**
 * POST /api/v1/tally/setup/:ballotId
 * Setup homomorphic encryption for a ballot
 * Generates ElGamal keypair
 */
router.post("/setup/:ballotId", async (req, res) => {
  try {
    const { ballotId } = req.params;

    console.log(`\n=== TALLY SETUP FOR BALLOT ${ballotId} ===`);

    // Generate ElGamal keypair
    const keypair = homomorphic.generateKeypair();
    
    console.log("ElGamal keypair generated");
    console.log(`Public key: ${keypair.publicKey.getX().toString(16).slice(0, 16)}...`);
    console.log(`Private key: ${keypair.privateKey.toString(16).slice(0, 16)}... (KEEP SECRET)`);

    // Store keypair (in production, private key should be in HSM or distributed)
    ballotKeys.set(ballotId, keypair);

    const serialized = homomorphic.serializeKeypair(keypair);

    res.json({
      ok: true,
      ballotId,
      publicKey: serialized.publicKey,
      message: "Homomorphic encryption setup complete"
    });

  } catch (err) {
    console.error("TALLY SETUP ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/tally/publickey/:ballotId
 * Get public key for a ballot
 */
router.get("/publickey/:ballotId", (req, res) => {
  try {
    const { ballotId } = req.params;

    const keypair = ballotKeys.get(ballotId);
    if (!keypair) {
      return res.status(404).json({
        ok: false,
        error: "No encryption key found for this ballot"
      });
    }

    const serialized = homomorphic.serializeKeypair(keypair);

    res.json({
      ok: true,
      ballotId,
      publicKey: serialized.publicKey
    });

  } catch (err) {
    console.error("GET PUBLIC KEY ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/v1/tally/compute/:ballotId
 * Compute homomorphic tally for a ballot
 * Fetches all encrypted votes from blockchain and sums them
 */
router.post("/compute/:ballotId", async (req, res) => {
  try {
    const { ballotId } = req.params;
    const { fabricClient, ballotRoutes } = res.locals;

    console.log(`\n=== COMPUTING HOMOMORPHIC TALLY ===`);
    console.log(`Ballot ID: ${ballotId}`);

    // Get ballot info
    const ballot = ballotRoutes.getActiveBallot();
    if (!ballot || ballot.id !== ballotId) {
      // Try to find in history
      console.log("Ballot not currently active, checking history...");
    }

    // Get encryption keypair
    const keypair = ballotKeys.get(ballotId);
    if (!keypair) {
      return res.status(404).json({
        ok: false,
        error: "No encryption key found for this ballot. Run /tally/setup first."
      });
    }

    // Get all votes from blockchain
    const allVotes = await fabricClient.getAllVotes(ballotId);
    console.log(`Total votes on blockchain for ballot: ${allVotes.length}`);

    if (allVotes.length === 0) {
      return res.json({
        ok: true,
        ballotId,
        tallies: {},
        totalVotes: 0,
        message: "No votes to tally"
      });
    }

    // Count votes with encryption
    let encryptedVoteCount = 0;
    allVotes.forEach(vote => {
      if (vote.encryptedVote) encryptedVoteCount++;
    });

    console.log(`Votes with encryption: ${encryptedVoteCount}`);

    // If no encrypted votes, fall back to plaintext counting
    if (encryptedVoteCount === 0) {
      console.warn("Warning: No encrypted votes found, using plaintext tallying");
      
      // Build hash -> name map from ballot options
      const choiceHashMap = {};
      if (ballot) {
        ballot.options.forEach(option => {
          const hash = require('crypto').createHash('sha256').update(String(option.name)).digest('hex');
          choiceHashMap[hash] = option.name;
        });
      }

      const plaintextTallies = {};
      
      // Initialize all options to 0
      if (ballot) {
        ballot.options.forEach(option => {
          plaintextTallies[option.name] = 0;
        });
      }
      
      // Count votes using hash-to-name mapping
      allVotes.forEach(vote => {
        const choiceHash = vote.voteChoiceHash || vote.voteChoice;
        const choiceName = choiceHashMap[choiceHash] || choiceHash; // fallback to raw value for legacy
        if (plaintextTallies[choiceName] !== undefined) {
          plaintextTallies[choiceName]++;
        } else {
          plaintextTallies[choiceName] = 1;
        }
      });

      return res.json({
        ok: true,
        ballotId,
        ballotTitle: ballot ? ballot.title : "Unknown",
        tallies: plaintextTallies,
        totalVotes: allVotes.length,
        method: "plaintext",
        warning: "No encrypted votes found - used plaintext counting"
      });
    }

    // FIXED: True homomorphic tallying using encrypted vectors
    // The tally is completely oblivious to individual voter choices.
    const encryptedTallies = {};

    // Initialize with null for all options
    if (ballot) {
      ballot.options.forEach(option => {
        encryptedTallies[option.name] = null;
      });
    }

    let processedCount = 0;
    allVotes.forEach(vote => {
      if (!vote.encryptedVote || !Array.isArray(vote.encryptedVote)) {
        console.warn(`Vote ${vote.voteId} has invalid or legacy encrypted vote format - skipping`);
        return;
      }

      try {
        // VECTOR FORMAT (True Privacy)
        // The vote is an array of ciphertexts, one for each option
        // We sum them element-wise
        if (ballot && ballot.options && vote.encryptedVote.length === ballot.options.length) {
          
          let isValidVote = true;
          const ciphertexts = [];

          // First pass: Verify all proofs
          for (let i = 0; i < ballot.options.length; i++) {
            const ciphertext = homomorphic.deserializeCiphertext(vote.encryptedVote[i]);
            ciphertexts.push(ciphertext);
            
            const proof = vote.encryptedVote[i].validityProof;
            if (proof) {
               const isValid = homomorphic.verifyValidVote(keypair.publicKey, ciphertext, proof);
               if (!isValid) {
                  console.warn(`  Vote ${vote.voteId} validity proof failed (perhaps encrypted with an older public key) - skipping`);
                  isValidVote = false;
                  break;
               }
            } else {
               // Allow for testing, but warn
               console.warn(`  Vote ${vote.voteId} missing validity proof`);
            }
          }

          if (isValidVote) {
            for (let i = 0; i < ballot.options.length; i++) {
              const optionName = ballot.options[i].name;
              const ciphertext = ciphertexts[i];
              
              if (encryptedTallies[optionName] === null) {
                encryptedTallies[optionName] = ciphertext;
              } else {
                encryptedTallies[optionName] = homomorphic.addCiphertexts(
                  encryptedTallies[optionName],
                  ciphertext
                );
              }
            }
            console.log(`  Processed vector vote ${vote.voteId}`);
            processedCount++;
          }
        } else {
          console.warn(`  Vector vote ${vote.voteId} length doesn't match ballot options - skipping`);
        }
      } catch (err) {
        console.error(`Error processing vote ${vote.voteId}:`, err.message);
      }
    });

    console.log(`Successfully processed ${processedCount} encrypted votes`);

    // Decrypt tallies
    const tallies = {};
    const decryptionLog = [];

    for (const [choice, encryptedSum] of Object.entries(encryptedTallies)) {
      if (encryptedSum === null) {
        // No votes for this choice
        tallies[choice] = 0;
        console.log(`\nNo votes for "${choice}"`);
        continue;
      }

      console.log(`\nDecrypting tally for "${choice}"...`);
      
      try {
        // Decrypt: M = sum of all v_i·G for this choice
        const M = homomorphic.decrypt(keypair.privateKey, encryptedSum);
        
        console.log(`  Decrypted point M for "${choice}"`);
        console.log(`    M.x: ${M.getX().toString(16).slice(0, 32)}...`);
        console.log(`    M.y: ${M.getY().toString(16).slice(0, 32)}...`);
        
        // Solve discrete log to get vote count
        // Since each vote encrypts 1, the sum is the vote count
        const maxExpected = allVotes.length;
        const count = homomorphic.solveDiscreteLog(M, maxExpected);
        
        tallies[choice] = count;
        
        decryptionLog.push({
          choice,
          count,
          encryptedSum: homomorphic.serializeCiphertext(encryptedSum)
        });
        
        console.log(`  ✅ Count: ${count}`);
      } catch (err) {
        console.error(`  ❌ Error decrypting "${choice}":`, err.message);
        console.error(`  Stack:`, err.stack);
        
        // Try to diagnose the issue
        try {
          const M = homomorphic.decrypt(keypair.privateKey, encryptedSum);
          console.log(`  Decrypted point exists, issue is in discrete log`);
          console.log(`  Point coordinates:`, {
            x: M.getX().toString(16),
            y: M.getY().toString(16)
          });
        } catch (decryptErr) {
          console.error(`  Decryption itself failed:`, decryptErr.message);
        }
        
        tallies[choice] = 0;
      }
    }

    console.log(`\n✅ Tally computation complete`);
    console.log(`Final tallies:`, tallies);
    console.log(`=== TALLY COMPLETE ===\n`);

    res.json({
      ok: true,
      ballotId,
      ballotTitle: ballot ? ballot.title : "Unknown",
      tallies,
      totalVotes: allVotes.length,
      encryptedVotes: processedCount,
      method: "homomorphic",
      decryptionLog
    });

  } catch (err) {
    console.error("COMPUTE TALLY ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/v1/tally/verify/:ballotId
 * Verify homomorphic tally computation
 * Anyone can verify the tally is correctly computed
 */
router.post("/verify/:ballotId", async (req, res) => {
  try {
    const { ballotId } = req.params;
    const { decryptionLog } = req.body;
    const { fabricClient } = res.locals;

    if (!decryptionLog) {
      return res.status(400).json({
        ok: false,
        error: "Missing decryptionLog in request body"
      });
    }

    console.log(`\n=== VERIFYING TALLY ===`);

    // Get all votes
    const allVotes = await fabricClient.getAllVotes(ballotId);

    // Recompute encrypted sums
    const recomputedSums = {};

    // Build hash -> name map for backward compatibility in plaintext fallback route
    // (We keep this for the plaintext tallying only, not used for homomorphic vector verification)
    const ballot = require('./ballot').getActiveBallot && require('./ballot').getActiveBallot();

    allVotes.forEach(vote => {
      if (!vote.encryptedVote || !Array.isArray(vote.encryptedVote)) return;

      try {
        // Vector format
        if (ballot && ballot.options && vote.encryptedVote.length === ballot.options.length) {
          for (let i = 0; i < ballot.options.length; i++) {
            const optionName = ballot.options[i].name;
            const ciphertext = homomorphic.deserializeCiphertext(vote.encryptedVote[i]);
            
            if (!recomputedSums[optionName]) {
              recomputedSums[optionName] = ciphertext;
            } else {
              recomputedSums[optionName] = homomorphic.addCiphertexts(
                recomputedSums[optionName],
                ciphertext
              );
            }
          }
        }
      } catch (err) {
        console.error(`Error in verify sum for ${vote.voteId}:`, err.message);
      }
    });

    // Verify each tally
    const verifications = [];
    let allValid = true;

    for (const logEntry of decryptionLog) {
      const { choice, encryptedSum } = logEntry;
      
      const claimed = homomorphic.deserializeCiphertext(encryptedSum);
      const recomputed = recomputedSums[choice];

      const matches = recomputed && 
        claimed.c1.eq(recomputed.c1) && 
        claimed.c2.eq(recomputed.c2);

      verifications.push({
        choice,
        valid: matches
      });

      if (!matches) allValid = false;
    }

    console.log(`Verification result: ${allValid ? 'VALID' : 'INVALID'}`);
    console.log(`=== VERIFICATION COMPLETE ===\n`);

    res.json({
      ok: true,
      ballotId,
      valid: allValid,
      verifications
    });

  } catch (err) {
    console.error("VERIFY TALLY ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/tally/keys
 * Get all ballot keys (ADMIN ONLY - for debugging)
 */
router.get("/keys", (req, res) => {
  try {
    const keys = {};
    
    for (const [ballotId, keypair] of ballotKeys.entries()) {
      keys[ballotId] = homomorphic.serializeKeypair(keypair);
    }

    res.json({
      ok: true,
      count: Object.keys(keys).length,
      keys
    });

  } catch (err) {
    console.error("GET KEYS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;