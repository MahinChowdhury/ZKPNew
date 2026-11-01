// ============================
// Sensor Registry Routes
// Authorised capture devices whose EdDSA keys may attest live samples
// (FINDINGS C6). The registry is public; only the registrar organisation
// can add to it (enforced by the chaincode).
// ============================

const express = require("express");

const router = express.Router();
const DECIMAL = /^[0-9]{1,78}$/;

/**
 * GET /api/v1/sensors — public registry [{ax, ay}] (clients build the Merkle path)
 */
router.get("/", async (req, res) => {
  try {
    res.json({ ok: true, sensors: await res.locals.fabricClient.getSensors() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/v1/sensors — register a device key { ax, ay } (RA)
 */
router.post("/", async (req, res) => {
  try {
    const { ax, ay } = req.body || {};
    if (!DECIMAL.test(String(ax || "")) || !DECIMAL.test(String(ay || ""))) {
      return res.status(400).json({ ok: false, error: "Body must be { ax, ay } as decimal strings" });
    }
    const result = await res.locals.fabricClient.registerSensor(String(ax), String(ay));
    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

module.exports = router;
