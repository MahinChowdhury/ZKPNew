// ============================
// Registration Route (RA enrolment)
//
// The voter's client generates the secret key, salt and commitment
// (frontend/src/crypto/voterClient.js). The RA receives only the NID,
// for deduplication, and the commitment C = H(H(template, salt), sk):
// it never sees sk, salt or the template, so it cannot link C to any
// later nullifier or ballot.
// ============================

const express = require("express");
const crypto = require("crypto");

const router = express.Router();

const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function hashNidNumber(nidNumber) {
  return crypto.createHash("sha256").update(String(nidNumber).trim()).digest("hex");
}

/**
 * POST /api/v1/register
 * Body (JSON): { nidNumber, biometricMode: "face" | "iris", commitment: decimal string }
 */
router.post("/", async (req, res) => {
  try {
    const { nidNumber, commitment } = req.body || {};
    const mode = req.body?.biometricMode || "face";
    const { fabricClient, snark, irisSnark } = res.locals;

    if (!nidNumber || !commitment) {
      return res.status(400).json({ ok: false, error: "Missing nidNumber or commitment" });
    }
    if (mode !== "face" && mode !== "iris") {
      return res.status(400).json({ ok: false, error: `Invalid biometricMode: ${mode}. Must be "face" or "iris".` });
    }
    if (!/^[0-9]{1,78}$/.test(String(commitment)) || BigInt(commitment) === 0n || BigInt(commitment) >= BN128_PRIME) {
      return res.status(400).json({ ok: false, error: "commitment must be a non-zero BN254 field element (decimal)" });
    }

    const nidHash = hashNidNumber(nidNumber);
    if (mode === "face") {
      await fabricClient.registerUser(nidHash, String(commitment));
      snark.invalidateMerkleCache();
    } else {
      await fabricClient.registerIrisUser(nidHash, String(commitment));
      irisSnark.invalidateIrisMerkleCache();
    }
    console.log(`✅ Registered ${mode} commitment for NID hash ${nidHash.slice(0, 12)}...`);

    res.json({ ok: true, biometricMode: mode });
  } catch (err) {
    console.error("REGISTER ERROR:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
