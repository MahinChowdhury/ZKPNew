// ============================
// Homomorphic Tally Routes — threshold trustees
// ============================
//
// The election key comes from a t-of-n DKG among trustees and is derived by
// the chaincode (finalizeBallotKey); no party holds the decryption key. The
// chaincode re-verifies the published tally (publishTally), and anyone can
// re-check it from public data (/verify).
//
// PROTOTYPE: the n trustees run in this process. Each Trustee object only
// ever uses its own shares, as separate machines would; in deployment each
// trustee runs crypto/threshold.js itself and posts its own transactions.

const express = require("express");
const homomorphic = require("../crypto/homomorphic");
const threshold = require("../crypto/threshold");

const { Trustee, tc } = threshold;

const router = express.Router();

const TRUSTEES = parseInt(process.env.TALLY_TRUSTEES || "3", 10);
const THRESHOLD = parseInt(process.env.TALLY_THRESHOLD || "2", 10);

// ballotId -> Trustee[] (prototype only, see above)
const ballotTrustees = new Map();

/**
 * POST /api/v1/tally/setup/:ballotId
 * Register the ballot with its trustee set, run the DKG on-chain and open voting.
 */
router.post("/setup/:ballotId", async (req, res) => {
  try {
    const { ballotId } = req.params;
    const { fabricClient, ballotRoutes } = res.locals;

    const ballot = ballotRoutes.getBallotById(ballotId);
    if (!ballot) {
      return res.status(404).json({ ok: false, error: `Ballot not found: ${ballotId}` });
    }
    if (ballotTrustees.has(ballotId)) {
      return res.status(409).json({ ok: false, error: "Ballot key already set up (on-chain record is write-once)" });
    }

    const trustees = Array.from({ length: TRUSTEES }, (_, i) => new Trustee(i + 1));
    await fabricClient.registerBallot(ballotId, ballot.options.length, trustees.map((t) => t.publicKey), THRESHOLD);

    // Each trustee posts its commitments and sends shares to the others
    const dealings = trustees.map((t) => t.deal(ballotId, THRESHOLD, TRUSTEES));
    for (const t of trustees) {
      const d = dealings[t.index - 1];
      await fabricClient.submitDealing(ballotId, t.index, d.commitments, d.sig);
    }
    for (const receiver of trustees) {
      for (const dealer of trustees) {
        const d = dealings[dealer.index - 1];
        const complaint = receiver.receive(ballotId, dealer.index, d.commitments, d.shares[receiver.index]);
        if (complaint) {
          await fabricClient.complain(ballotId, complaint.complainer, complaint.dealer, complaint.share, complaint.sig);
        }
      }
    }
    const { publicKey, qual } = await fabricClient.finalizeBallotKey(ballotId);
    trustees.forEach((t) => t.finalize(qual));
    ballotTrustees.set(ballotId, trustees);

    console.log(`Ballot ${ballotId}: ${THRESHOLD}-of-${TRUSTEES} key generated, QUAL = [${qual}]`);
    res.json({ ok: true, ballotId, publicKey, threshold: THRESHOLD, trustees: TRUSTEES, qual });
  } catch (err) {
    console.error("TALLY SETUP ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/tally/publickey/:ballotId — the election key, from the ledger
 */
router.get("/publickey/:ballotId", async (req, res) => {
  try {
    const chain = await res.locals.fabricClient.getBallot(req.params.ballotId);
    if (!chain.publicKey) {
      return res.status(404).json({ ok: false, error: "Key generation has not finished for this ballot" });
    }
    res.json({ ok: true, ballotId: req.params.ballotId, publicKey: chain.publicKey });
  } catch (err) {
    res.status(404).json({ ok: false, error: err.message });
  }
});

// Sum each option's ciphertexts over the ballots on the ledger, re-verifying
// every ballot proof so the tally never rests on the endorsers alone.
function aggregate(votes, chain, ballotId) {
  const pk = homomorphic.deserializeCiphertext({ c1: chain.publicKey, c2: chain.publicKey }).c1;
  const valid = votes.filter((vote) => {
    const enc = vote.encryptedVote;
    if (!enc || !Array.isArray(enc.ciphertexts) || enc.ciphertexts.length !== chain.numOptions) return false;
    const cts = enc.ciphertexts.map((c) => homomorphic.deserializeCiphertext(c));
    const ok = enc.ciphertexts.every((c, i) => c.validityProof &&
      homomorphic.verifyValidVote(pk, cts[i], c.validityProof, homomorphic.optionContext(ballotId, vote.nullifier, i))) &&
      homomorphic.verifySumIsOne(pk, cts, enc.sumProof, homomorphic.sumContext(ballotId, vote.nullifier));
    if (!ok) console.warn(`  Vote ${vote.voteId} failed ballot proof verification - skipping`);
    return ok;
  });
  return { sums: threshold.aggregate(valid.map((v) => v.encryptedVote), chain.numOptions), counted: valid.length };
}

/**
 * POST /api/v1/tally/compute/:ballotId
 * Close voting, collect t partial decryptions per option, publish on-chain.
 */
router.post("/compute/:ballotId", async (req, res) => {
  try {
    const { ballotId } = req.params;
    const { fabricClient, ballotRoutes } = res.locals;
    const ballot = ballotRoutes.getBallotById(ballotId);
    const trustees = ballotTrustees.get(ballotId);
    if (!ballot || !trustees) {
      return res.status(404).json({ ok: false, error: "Unknown ballot or no trustees. Run /tally/setup first." });
    }

    let chain = await fabricClient.getBallot(ballotId);
    if (chain.status === "open") {
      await fabricClient.closeBallot(ballotId);
      chain = await fabricClient.getBallot(ballotId);
    }

    const votes = await fabricClient.getAllVotes(ballotId);
    const { sums, counted } = aggregate(votes, chain, ballotId);

    // Any t trustees of QUAL suffice; here, the first t. A failed discrete
    // log means an aggregate is not a valid count: fail rather than publish.
    const active = trustees.filter((t) => chain.qual.includes(t.index)).slice(0, chain.threshold);
    const { options } = threshold.decryptTally(ballotId, sums, active, votes.length);

    const published = await fabricClient.publishTally(ballotId, { options });
    const tallies = {};
    ballot.options.forEach((o, j) => { tallies[o.name] = published.totals[j]; });

    res.json({
      ok: true,
      ballotId,
      ballotTitle: ballot.title,
      tallies,
      totalVotes: published.numVotes,
      encryptedVotes: counted,
      method: `homomorphic, ${chain.threshold}-of-${chain.trustees.length} threshold decryption`,
      tally: { options },
    });
  } catch (err) {
    console.error("COMPUTE TALLY ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/v1/tally/verify/:ballotId
 * Re-check a tally from public data only: the ledger's ballots, the DKG
 * transcript and the partial decryptions. Checks the on-chain tally, or a
 * candidate { options } given in the body.
 */
router.post("/verify/:ballotId", async (req, res) => {
  try {
    const { ballotId } = req.params;
    const { fabricClient } = res.locals;
    const chain = await fabricClient.getBallot(ballotId);
    const tally = req.body && req.body.options ? req.body : await fabricClient.getTally(ballotId);

    const votes = await fabricClient.getAllVotes(ballotId);
    const { sums } = aggregate(votes, chain, ballotId);
    const key = {
      threshold: chain.threshold,
      trustees: chain.trustees.length,
      qualDealings: chain.qual.map((i) => chain.dealings[i]),
    };
    const verifications = tally.options.map((entry, j) => {
      try {
        if (!sums[j]) {
          if (entry.total !== 0) throw new Error("no ballots, total must be 0");
        } else {
          tc.verifyOptionTally(key, sums[j], j, ballotId, entry);
        }
        return { option: j, total: entry.total, valid: true };
      } catch (e) {
        return { option: j, total: entry.total, valid: false, error: e.message };
      }
    });
    const valid = verifications.length === chain.numOptions && verifications.every((v) => v.valid);
    res.json({ ok: true, ballotId, valid, verifications });
  } catch (err) {
    console.error("VERIFY TALLY ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/tally/keys — election public keys and trustee sets (never secrets)
 */
router.get("/keys", async (req, res) => {
  try {
    const keys = {};
    for (const ballotId of ballotTrustees.keys()) {
      const chain = await res.locals.fabricClient.getBallot(ballotId);
      keys[ballotId] = { publicKey: chain.publicKey, threshold: chain.threshold, trustees: chain.trustees };
    }
    res.json({ ok: true, count: Object.keys(keys).length, keys });
  } catch (err) {
    console.error("GET KEYS ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
