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

    // 4. Derive k
    const salt = crypto.randomBytes(16).toString("hex");
    const k = deriveK(faceHash, salt);

    // 5. S = kG
    const S = ec.g.mul(k);
    const Sx = S.getX().toString(16);
    const Sy = S.getY().toString(16);

    console.log("Sx:", Sx);
    console.log("Sy:", Sy);
    console.log("Salt:", salt);

    // 6. Register on blockchain
    await fabricClient.registerUser(nidHash, Sx, Sy, salt);
    console.log("✅ Registered on blockchain");

    // 7. QR payload
    const qrPayload = {
      nidHash,
      faceHash,
      salt,
      faceEmbedding: embedding  // Store embedding in QR
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
// LOGIN
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

      console.log("\n=== LOGIN START ===");

      // 1. Decode QR
      const encrypted = await decodeQRCode(qrFile);
      console.log("✅ QR decoded");

      // 2. Decrypt QR
      const qrData = decryptPayload(encrypted, password);
      console.log("✅ QR decrypted");
      console.log("QR Data keys:", Object.keys(qrData));

      // 3. Get login embedding
      const faceLogin = await getFaceEmbedding(faceFile);
      console.log("✅ Login face embedding extracted");

      // 4. Compare embeddings
      // Use faceEmbedding from QR (not face_reg)
      const registeredEmbedding = qrData.faceEmbedding;
      
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      console.log("Registered embedding dimension:", registeredEmbedding.length);
      
      const isMatch = await compareEmbeddings(faceLogin, registeredEmbedding);
      console.log("Face match result:", isMatch);

      // 5. Get blockchain data
      const userData = await fabricClient.getUserData(qrData.nidHash);
      const { Sx, Sy, salt } = userData;
      console.log("✅ Retrieved from blockchain");

      // 6. ZKP Verification
      const S = ec.curve.point(new BN(Sx, 16), new BN(Sy, 16));
      const k = deriveK(qrData.faceHash, salt);
      const S2 = ec.g.mul(k);

      const zkpVerified =
        S2.getX().eq(new BN(Sx, 16)) && S2.getY().eq(new BN(Sy, 16));

      console.log("ZKP verification:", zkpVerified);

      const loginSuccess = isMatch && zkpVerified;

      console.log("=== LOGIN COMPLETE ===");
      console.log("Result:", loginSuccess ? "SUCCESS ✅" : "FAILED ❌");
      console.log("");

      res.json({
        ok: loginSuccess,
        isMatch,
        isVerified: zkpVerified,
        nidHash: qrData.nidHash,
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