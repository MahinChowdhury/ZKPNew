// ============================================================
// attestor.js — capture-device attestation service (port 8001)
//
// Stands in for the trusted camera / kiosk. It is a separate trust domain
// from the API gateway: in deployment its key lives in the device's secure
// element. It receives the image, gets the reading from the biometric
// extractor (model/app.py), and returns the signed circuit template.
// It never sees the voter's credential, nullifier or vote.
//
// Run:   node sensor/attestor.js
// Then register its public key once (RA):
//   curl -X POST localhost:3000/api/v1/sensors -H 'Content-Type: application/json' \
//        -d "$(curl -s localhost:8001/public-key)"
// ============================================================

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const axios = require("axios");
const FormData = require("form-data");
const { loadSigner, attest } = require("./attest-core");

const PORT = process.env.SENSOR_PORT || 8001;
const EXTRACTOR = process.env.BIOMETRIC_URL || "http://localhost:8000";
const KEY_FILE = process.env.SENSOR_KEY_FILE || path.join(__dirname, "sensor_key.json");
const DECIMAL = /^[0-9]{1,78}$/;

async function main() {
  // Persist the device key so its on-chain registration survives restarts
  let saved = null;
  if (fs.existsSync(KEY_FILE)) saved = JSON.parse(fs.readFileSync(KEY_FILE, "utf8")).privateKeyHex;
  const signer = await loadSigner(process.env.SENSOR_PRIVATE_KEY || saved);
  if (!saved && !process.env.SENSOR_PRIVATE_KEY) {
    fs.writeFileSync(KEY_FILE, JSON.stringify({ privateKeyHex: signer.privateKeyHex }), { mode: 0o600 });
  }

  const app = express();
  app.use(cors({ origin: (process.env.CLIENT_ORIGINS || "http://localhost:5173").split(",") }));
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

  app.get("/public-key", (req, res) => res.json(signer.publicKey));

  /**
   * POST /attest  (multipart)
   *   file           live image
   *   mode           "face" | "iris"
   *   electionId     decimal
   *   sessionCommit  decimal (from voterClient.startVoteSession)
   */
  app.post("/attest", upload.single("file"), async (req, res) => {
    try {
      const { mode, electionId, sessionCommit } = req.body;
      if (!req.file || (mode !== "face" && mode !== "iris") || !DECIMAL.test(electionId || "") || !DECIMAL.test(sessionCommit || "")) {
        return res.status(400).json({ ok: false, error: "Required: file, mode (face|iris), electionId, sessionCommit" });
      }
      const form = new FormData();
      form.append("file", req.file.buffer, { filename: req.file.originalname, contentType: req.file.mimetype });
      const url = mode === "face" ? "/face/get-embedding" : "/iris/get-iriscode";
      const { data } = await axios.post(EXTRACTOR + url, form, { headers: form.getHeaders() });
      const reading = mode === "face" ? data.embedding : { irisCode: data.iris_code, noiseMask: data.noise_mask };

      res.json({ ok: true, ...(await attest(signer, { mode, reading, electionId, sessionCommit })) });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.response?.data?.detail || err.message });
    }
  });

  app.listen(PORT, () => {
    console.log(`📷 Capture-device attestor on http://localhost:${PORT} (extractor: ${EXTRACTOR})`);
    console.log(`   Public key: ${JSON.stringify(signer.publicKey)}`);
    console.log(`   ⚠ No PAD/liveness model deployed — signatures attest provenance only (FINDINGS C25)`);
  });
}

main().catch((e) => { console.error(e); process.exit(1); });
