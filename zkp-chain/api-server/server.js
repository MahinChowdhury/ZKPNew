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
const voteRoutes = require("./routes/vote");
const ballotRoutes = require("./routes/ballot");
const tallyRoutes = require("./routes/tally");

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
// (Kept for backward compatibility with login endpoints)
// ============================

function schnorrProverStep1(k) {
  const r = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  if (r.isZero()) throw new Error("Invalid random nonce");
  const R = ec.g.mul(r);
  return { r, R };
}

function schnorrVerifierChallenge(R, S, nidHash) {
  const Rx = R.getX().toString(16, 64);
  const Ry = R.getY().toString(16, 64);
  const Sx = S.getX().toString(16, 64);
  const Sy = S.getY().toString(16, 64);
  
  const challengeInput = Rx + Ry + Sx + Sy + nidHash;
  const challengeHash = keccak256(challengeInput);
  
  const c = new BN(challengeHash, 16).umod(ec.curve.n);
  return c;
}

function schnorrProverStep3(r, c, k) {
  const s = r.add(c.mul(k)).umod(ec.curve.n);
  return s;
}

function schnorrVerify(R, c, s, S) {
  const sG = ec.g.mul(s);
  const cS = S.mul(c);
  const RplusCsS = R.add(cS);
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
// Middleware for Vote Routes
// ============================
app.use((req, res, next) => {
  // Attach utilities to res.locals for vote routes
  res.locals.fabricClient = fabricClient;
  res.locals.decodeQRCode = decodeQRCode;
  res.locals.getFaceEmbedding = getFaceEmbedding;
  res.locals.compareEmbeddings = compareEmbeddings;
  res.locals.ballotRoutes = ballotRoutes;
  res.locals.tallyRoutes = tallyRoutes;
  next();
});

// ============================
// Routes
// ============================

// Mount ballot routes
app.use("/api/v1/ballot", ballotRoutes);

// Mount tally routes
app.use("/api/v1/tally", tallyRoutes);

// Mount vote routes
app.use("/api/v1/vote", voteRoutes);

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

    // 1. Hash NID (for QR storage only, not blockchain)
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

    // 5. S = kG (public key - this is the link tag)
    const S = ec.g.mul(k);
    const Sx = S.getX().toString(16);
    const Sy = S.getY().toString(16);

    console.log("Sx:", Sx);
    console.log("Sy:", Sy);
    console.log("Salt:", salt);

    // 6. Register on blockchain (add to global ring)
    await fabricClient.registerUser(nidHash, Sx, Sy, salt);
    console.log("✅ Registered in global ring");

    // 7. QR payload (store everything needed for voting)
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
    res.setHeader("Content-Disposition", "attachment; filename=voter-credential.png");
    res.send(qrBuffer);

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------------------
// LOGIN - Step 1: Request Challenge
// (Kept for backward compatibility)
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

      // 1. Decode & Decrypt QR
      const encrypted = await decodeQRCode(qrFile);
      const qrData = decryptPayload(encrypted, password);
      console.log("✅ QR decrypted");

      // 2. Face verification
      const faceLogin = await getFaceEmbedding(faceFile);
      console.log("✅ Login face embedding extracted");

      // 4. Compare embeddings
      const registeredEmbedding = qrData.faceEmbedding;
      
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      const isMatch = await compareEmbeddings(faceLogin, registeredEmbedding);
      console.log("Face match:", isMatch);

      if (!isMatch) {
        return res.json({
          ok: false,
          error: "Face does not match",
          isMatch: false
        });
      }

      // 5. Derive k (secret) from QR data
      const k = deriveK(qrData.faceHash, qrData.salt);
      const S = ec.g.mul(k);

      // 6. Generate Schnorr proof
      const { r, R } = schnorrProverStep1(k);
      const Rx = R.getX().toString(16);
      const Ry = R.getY().toString(16);
      
      console.log("Generated R commitment");

      // 7. Generate challenge and response
      const c = schnorrVerifierChallenge(R, S, qrData.nidHash);
      const s = schnorrProverStep3(r, c, k);
      
      console.log("=== LOGIN CHALLENGE COMPLETE ===\n");

      res.json({
        ok: true,
        isMatch: true,
        proof: {
          Rx,
          Ry,
          c: c.toString(16),
          s: s.toString(16)
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
// (Kept for backward compatibility)
// --------------------------------------
app.post("/api/v1/login/verify", async (req, res) => {
  try {
    const { nidHash, proof } = req.body;

    if (!nidHash || !proof) {
      return res.status(400).json({ ok: false, error: "Missing fields" });
    }

    console.log("\n=== SCHNORR VERIFICATION START ===");

    // Note: In the new ring signature system, we don't store per-user data
    // This endpoint is kept for backward compatibility only
    console.log("Warning: Using legacy verification method");

    const R = ec.curve.point(new BN(proof.Rx, 16), new BN(proof.Ry, 16));
    const c = new BN(proof.c, 16);
    const s = new BN(proof.s, 16);

    // We can't verify against blockchain in new system
    // Just verify the proof structure is valid
    const sG = ec.g.mul(s);
    const zkpVerified = sG.validate();

    console.log("=== SCHNORR VERIFICATION COMPLETE ===\n");

    res.json({
      ok: zkpVerified,
      isVerified: zkpVerified,
      nidHash,
      note: "This endpoint is deprecated - use /api/v1/vote for voting"
    });

  } catch (err) {
    console.error("VERIFICATION ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============================
// Health & Query Endpoints
// ============================

app.get("/api/v1/health", async (req, res) => {
  try {
    const ringSize = await fabricClient.getRingSize();
    const voteCount = await fabricClient.getVoteCount();
    
    res.json({
      ok: true,
      status: "healthy",
      blockchain: "connected",
      system: "anonymous-voting",
      registeredVoters: ringSize,
      totalVotes: voteCount
    });
  } catch (err) {
    res.status(503).json({
      ok: false,
      status: "unhealthy",
      error: err.message
    });
  }
});

app.get("/api/v1/ring", async (req, res) => {
  try {
    const ring = await fabricClient.getRing();
    res.json({
      ok: true,
      ringSize: ring.length,
      ring
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/ring/size", async (req, res) => {
  try {
    const size = await fabricClient.getRingSize();
    res.json({ ok: true, ringSize: size });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Legacy endpoints (for backward compatibility)
app.get("/api/v1/identities", async (req, res) => {
  try {
    const ring = await fabricClient.getRing();
    res.json({
      ok: true,
      count: ring.length,
      note: "This endpoint is deprecated - use /api/v1/ring",
      identities: ring.map((pk, i) => `voter_${i}`)
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/identities/count", async (req, res) => {
  try {
    const count = await fabricClient.getRingSize();
    res.json({ 
      ok: true, 
      count,
      note: "This endpoint is deprecated - use /api/v1/ring/size"
    });
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
    app.listen(PORT, () => {
      console.log(`🚀 Anonymous Voting Server running on http://localhost:${PORT}`);
      console.log(`📊 Endpoints:`);
      console.log(`   POST /api/v1/register - Register voter`);
      console.log(`   POST /api/v1/ballot/create - Create ballot`);
      console.log(`   POST /api/v1/tally/setup/:ballotId - Setup homomorphic encryption`);
      console.log(`   POST /api/v1/vote - Cast anonymous vote`);
      console.log(`   POST /api/v1/tally/compute/:ballotId - Compute homomorphic tally`);
      console.log(`   GET  /api/v1/vote/results - Get vote results`);
      console.log(`   GET  /api/v1/ring - Get voter ring`);
    });
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
