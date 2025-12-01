// ============================
// Imports & Setup
// ============================
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const crypto = require("crypto");
const QRCode = require("qrcode");
const Jimp = require("jimp");
const jsQR = require("jsqr");
const axios = require("axios");
const FormData = require("form-data");
const EC = require("elliptic").ec;
const BN = require("bn.js");
const FabricClient = require("./fabric-client");

require("dotenv").config();

const ec = new EC("secp256k1");
const app = express();
const PORT = process.env.PORT || 3000;

// ============================
// Fabric Client Setup
// ============================
const fabricClient = new FabricClient();

// ============================
// Middleware
// ============================
app.use(cors());
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage() });

// ============================
// Utility Functions
// ============================

function keccak256(data) {
  if (data === undefined || data === null) {
    throw new Error("keccak256() received undefined data");
  }
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}

function hashNidNumber(nidNumber) {
  return keccak256(nidNumber.trim());
}

function encryptPayload(payload, password) {
  const key = crypto.createHash("sha256").update(password).digest();
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(JSON.stringify(payload), "utf8", "base64");
  encrypted += cipher.final("base64");

  return { iv: iv.toString("base64"), data: encrypted };
}

function decryptPayload(encryptedPayload, password) {
  const { iv, data } = JSON.parse(encryptedPayload);
  const key = crypto.createHash("sha256").update(password).digest();
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    key,
    Buffer.from(iv, "base64")
  );

  let decrypted = decipher.update(data, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}

async function decodeQRCode(file) {
  const img = await Jimp.read(file.buffer);
  const { data, width, height } = img.bitmap;
  const code = jsQR(new Uint8ClampedArray(data), width, height);
  if (!code) throw new Error("Unable to decode QR code");
  return code.data;
}

function deriveK(faceHash, salt) {
  const hash = keccak256(faceHash + salt);
  let k = new BN(hash, 16).umod(ec.curve.n);
  if (k.isZero()) k = k.iaddn(1);
  return k;
}

// ============================
// Schnorr ZKP Functions
// ============================

/**
 * Generate Schnorr proof commitment (Step 1: Prover)
 * @param {BN} k - The secret scalar
 * @returns {{ r: BN, R: Point }} - Random nonce and commitment R = rG
 */
function schnorrProverStep1(k) {
  // Generate random nonce r ∈ [1, n-1]
  const r = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  if (r.isZero()) throw new Error("Invalid random nonce");
  
  // Compute R = rG
  const R = ec.g.mul(r);
  
  return { r, R };
}

/**
 * Generate Schnorr challenge (Step 2: Verifier)
 * @param {Point} R - Commitment from prover
 * @param {Point} S - Public key S = kG
 * @param {string} nidHash - Context binding
 * @returns {BN} challenge c
 */
function schnorrVerifierChallenge(R, S, nidHash) {
  // Create challenge: c = H(R || S || nidHash)
  const Rx = R.getX().toString(16, 64);
  const Ry = R.getY().toString(16, 64);
  const Sx = S.getX().toString(16, 64);
  const Sy = S.getY().toString(16, 64);
  
  const challengeInput = Rx + Ry + Sx + Sy + nidHash;
  const challengeHash = keccak256(challengeInput);
  
  const c = new BN(challengeHash, 16).umod(ec.curve.n);
  return c;
}

/**
 * Generate Schnorr response (Step 3: Prover)
 * @param {BN} r - Random nonce from step 1
 * @param {BN} c - Challenge from verifier
 * @param {BN} k - The secret scalar
 * @returns {BN} response s = r + c·k mod n
 */
function schnorrProverStep3(r, c, k) {
  // Compute s = r + c·k mod n
  const s = r.add(c.mul(k)).umod(ec.curve.n);
  return s;
}

/**
 * Verify Schnorr proof (Step 4: Verifier)
 * @param {Point} R - Commitment from prover
 * @param {BN} c - Challenge that was sent
 * @param {BN} s - Response from prover
 * @param {Point} S - Public key S = kG
 * @returns {boolean} true if proof is valid
 */
function schnorrVerify(R, c, s, S) {
  // Verify: sG = R + cS
  const sG = ec.g.mul(s);
  const cS = S.mul(c);
  const RplusCsS = R.add(cS);
  
  // Check if points are equal
  return sG.eq(RplusCsS);
}

// ============================
// External Python API
// ============================

async function getFaceEmbedding(file) {
  const form = new FormData();
  form.append("file", file.buffer, {
    filename: file.originalname,
    contentType: file.mimetype,
  });

  const res = await axios.post("http://localhost:8000/get-embedding", form, {
    headers: form.getHeaders(),
  });

  if (!res.data || !res.data.embedding) {
    throw new Error("Python API did not return embedding");
  }

  return res.data.embedding;
}

async function compareEmbeddings(faceLogin, faceReg) {
  console.log("Comparing embeddings...");
  console.log("Login embedding length:", faceLogin.length);
  console.log("Registered embedding length:", faceReg.length);
  
  const res = await axios.post("http://localhost:8000/compare-embeddings", {
    face_login: faceLogin,
    face_reg: faceReg,
  });
  
  console.log("Comparison result:", res.data);
  return res.data.is_same_person;
}

// ============================
// Routes
// ============================

// --------------------------------------
// REGISTER
// --------------------------------------
app.post("/api/v1/register", upload.single("faceImg"), async (req, res) => {
  try {
    const { nidNumber, password } = req.body;
    const faceFile = req.file;

    if (!nidNumber || !password || !faceFile) {
      return res.status(400).json({ ok: false, error: "Missing fields" });
    }

    console.log("\n=== REGISTRATION START ===");

    // 1. Hash NID
    const nidHash = hashNidNumber(nidNumber);
    console.log("NID Hash:", nidHash);

    // 2. Get embedding
    const embedding = await getFaceEmbedding(faceFile);
    console.log("Embedding dimension:", embedding.length);

    // 3. Face hash
    const faceHash = keccak256(JSON.stringify(embedding));
    console.log("Face Hash:", faceHash);

    // 4. Derive k (this becomes the secret)
    const salt = crypto.randomBytes(16).toString("hex");
    const k = deriveK(faceHash, salt);

    // 5. S = kG (public key)
    const S = ec.g.mul(k);
    const Sx = S.getX().toString(16);
    const Sy = S.getY().toString(16);

    console.log("Sx:", Sx);
    console.log("Sy:", Sy);
    console.log("Salt:", salt);

    // 6. Register on blockchain (store S, not k)
    await fabricClient.registerUser(nidHash, Sx, Sy, salt);
    console.log("✅ Registered on blockchain");

    // 7. QR payload (store k indirectly via faceHash + salt)
    const qrPayload = {
      nidHash,
      faceHash,
      salt,
      faceEmbedding: embedding
    };

    // 8. Encrypt
    const encrypted = encryptPayload(qrPayload, password);

    // 9. Generate QR
    const qrBuffer = await QRCode.toBuffer(JSON.stringify(encrypted), {
      errorCorrectionLevel: "L"
    });

    console.log("=== REGISTRATION COMPLETE ===\n");

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Content-Disposition", "attachment; filename=qr-code.png");
    res.send(qrBuffer);

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------------------
// LOGIN - Step 1: Request Challenge
// --------------------------------------
app.post(
  "/api/v1/login/challenge",
  upload.fields([{ name: "qrCode" }, { name: "faceImg" }]),
  async (req, res) => {
    try {
      const { password } = req.body;
      const qrFile = req.files.qrCode?.[0];
      const faceFile = req.files.faceImg?.[0];

      if (!password || !qrFile || !faceFile) {
        return res.status(400).json({ ok: false, error: "Missing fields" });
      }

      console.log("\n=== LOGIN CHALLENGE START ===");

      // 1. Decode QR
      const encrypted = await decodeQRCode(qrFile);
      console.log("✅ QR decoded");

      // 2. Decrypt QR
      const qrData = decryptPayload(encrypted, password);
      console.log("✅ QR decrypted");

      // 3. Get login embedding
      const faceLogin = await getFaceEmbedding(faceFile);
      console.log("✅ Login face embedding extracted");

      // 4. Compare embeddings
      const registeredEmbedding = qrData.faceEmbedding;
      
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      const isMatch = await compareEmbeddings(faceLogin, registeredEmbedding);
      console.log("Face match result:", isMatch);

      if (!isMatch) {
        return res.json({
          ok: false,
          error: "Face does not match",
          isMatch: false
        });
      }

      // 5. Derive k (secret) from QR data
      const k = deriveK(qrData.faceHash, qrData.salt);

      // 6. Schnorr Step 1: Generate commitment
      const { r, R } = schnorrProverStep1(k);
      
      const Rx = R.getX().toString(16);
      const Ry = R.getY().toString(16);
      
      console.log("Generated R commitment");
      console.log("Rx:", Rx);
      console.log("Ry:", Ry);

      // 7. Get blockchain data for verification
      const userData = await fabricClient.getUserData(qrData.nidHash);
      const { Sx, Sy } = userData;
      const S = ec.curve.point(new BN(Sx, 16), new BN(Sy, 16));

      // 8. Schnorr Step 2: Generate challenge
      const c = schnorrVerifierChallenge(R, S, qrData.nidHash);
      const cHex = c.toString(16);
      
      console.log("Generated challenge c:", cHex);

      // 9. Schnorr Step 3: Generate response
      const s = schnorrProverStep3(r, c, k);
      const sHex = s.toString(16);
      
      console.log("Generated response s:", sHex);
      console.log("=== LOGIN CHALLENGE COMPLETE ===\n");

      // Return the proof components
      res.json({
        ok: true,
        isMatch: true,
        proof: {
          Rx,
          Ry,
          c: cHex,
          s: sHex
        },
        nidHash: qrData.nidHash
      });

    } catch (err) {
      console.error("LOGIN CHALLENGE ERROR:", err);
      res.status(500).json({ ok: false, error: err.message });
    }
  }
);

// --------------------------------------
// LOGIN - Step 2: Verify Proof
// --------------------------------------
app.post("/api/v1/login/verify", async (req, res) => {
  try {
    const { nidHash, proof } = req.body;

    if (!nidHash || !proof) {
      return res.status(400).json({ ok: false, error: "Missing fields" });
    }

    console.log("\n=== SCHNORR VERIFICATION START ===");

    // 1. Get blockchain data
    const userData = await fabricClient.getUserData(nidHash);
    const { Sx, Sy } = userData;
    
    // 2. Reconstruct points
    const S = ec.curve.point(new BN(Sx, 16), new BN(Sy, 16));
    const R = ec.curve.point(new BN(proof.Rx, 16), new BN(proof.Ry, 16));
    const c = new BN(proof.c, 16);
    const s = new BN(proof.s, 16);

    console.log("Verifying proof...");
    console.log("S (public key):", Sx.slice(0, 16) + "...");
    console.log("R (commitment):", proof.Rx.slice(0, 16) + "...");
    console.log("c (challenge):", proof.c.slice(0, 16) + "...");
    console.log("s (response):", proof.s.slice(0, 16) + "...");

    // 3. Schnorr Step 4: Verify proof
    const zkpVerified = schnorrVerify(R, c, s, S);

    console.log("ZKP verification result:", zkpVerified);
    console.log("=== SCHNORR VERIFICATION COMPLETE ===");
    console.log("Result:", zkpVerified ? "SUCCESS ✅" : "FAILED ❌");
    console.log("");

    res.json({
      ok: zkpVerified,
      isVerified: zkpVerified,
      nidHash
    });

  } catch (err) {
    console.error("VERIFICATION ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------------------
// LEGACY LOGIN (Combined - for backward compatibility)
// --------------------------------------
app.post(
  "/api/v1/login",
  upload.fields([{ name: "qrCode" }, { name: "faceImg" }]),
  async (req, res) => {
    try {
      const { password } = req.body;
      const qrFile = req.files.qrCode?.[0];
      const faceFile = req.files.faceImg?.[0];

      if (!password || !qrFile || !faceFile) {
        return res.status(400).json({ ok: false, error: "Missing fields" });
      }

      console.log("\n=== COMBINED LOGIN START ===");

      // 1. Decode & Decrypt QR
      const encrypted = await decodeQRCode(qrFile);
      const qrData = decryptPayload(encrypted, password);
      console.log("✅ QR decrypted");

      // 2. Face verification
      const faceLogin = await getFaceEmbedding(faceFile);
      const registeredEmbedding = qrData.faceEmbedding;
      
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      const isMatch = await compareEmbeddings(faceLogin, registeredEmbedding);
      console.log("Face match:", isMatch);

      if (!isMatch) {
        return res.json({
          ok: false,
          isMatch: false,
          isVerified: false,
          nidHash: qrData.nidHash
        });
      }

      // 3. Schnorr ZKP
      const k = deriveK(qrData.faceHash, qrData.salt);
      const { r, R } = schnorrProverStep1(k);
      
      const userData = await fabricClient.getUserData(qrData.nidHash);
      const S = ec.curve.point(new BN(userData.Sx, 16), new BN(userData.Sy, 16));
      
      const c = schnorrVerifierChallenge(R, S, qrData.nidHash);
      const s = schnorrProverStep3(r, c, k);
      
      const zkpVerified = schnorrVerify(R, c, s, S);
      console.log("ZKP verified:", zkpVerified);

      const loginSuccess = isMatch && zkpVerified;

      console.log("=== COMBINED LOGIN COMPLETE ===");
      console.log("Result:", loginSuccess ? "SUCCESS ✅" : "FAILED ❌\n");

      res.json({
        ok: loginSuccess,
        isMatch,
        isVerified: zkpVerified,
        nidHash: qrData.nidHash
      });

    } catch (err) {
      console.error("LOGIN ERROR:", err);
      res.status(500).json({ ok: false, error: err.message });
    }
  }
);

// ============================
// Health & Query Endpoints
// ============================

app.get("/api/v1/health", async (req, res) => {
  try {
    const count = await fabricClient.getRegisteredCount();
    res.json({
      ok: true,
      status: "healthy",
      blockchain: "connected",
      registeredCount: count
    });
  } catch (err) {
    res.status(503).json({
      ok: false,
      status: "unhealthy",
      error: err.message
    });
  }
});

app.get("/api/v1/identities", async (req, res) => {
  try {
    const identities = await fabricClient.getAllRegistered();
    res.json({
      ok: true,
      count: identities.length,
      identities
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/identities/count", async (req, res) => {
  try {
    const count = await fabricClient.getRegisteredCount();
    res.json({ ok: true, count });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============================
// Server Startup
// ============================
async function startServer() {
  try {
    await fabricClient.connect();
    app.listen(PORT, () =>
      console.log(`🚀 Server running on http://localhost:${PORT}`)
    );
  } catch (err) {
    console.error("Startup failed:", err);
    process.exit(1);
  }
}

process.on("SIGINT", async () => {
  console.log("\nShutting down...");
  await fabricClient.disconnect();
  process.exit(0);
});

startServer();
