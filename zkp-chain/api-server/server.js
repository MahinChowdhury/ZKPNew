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
const snark = require("./crypto/snark");

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

function sha256Hash(data) {
  if (data === undefined || data === null) {
    throw new Error("sha256Hash() received undefined data");
  }
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}

function hashNidNumber(nidNumber) {
  return sha256Hash(nidNumber.trim());
}

function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
}

function encryptPayload(payload, password) {
  const iv = crypto.randomBytes(16);
  const pbkdfSalt = crypto.randomBytes(16);
  const key = deriveKeyFromPassword(password, pbkdfSalt);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(JSON.stringify(payload), "utf8", "base64");
  encrypted += cipher.final("base64");

  return { iv: iv.toString("base64"), salt: pbkdfSalt.toString("base64"), data: encrypted };
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

async function decodeQRCode(file) {
  const img = await Jimp.read(file.buffer);
  const { data, width, height } = img.bitmap;
  const code = jsQR(new Uint8ClampedArray(data), width, height);
  if (!code) throw new Error("Unable to decode QR code");
  return code.data;
}

// Legacy secp256k1 key derivation — kept for LRS (ring signatures)
function deriveK(faceHash, salt) {
  const hash = sha256Hash(faceHash + salt);
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
  res.locals.snark = snark;
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
// Uses ZK-SNARK (Poseidon + Baby Jubjub)
// for identity commitment, plus secp256k1
// public key for LRS ring membership.
// --------------------------------------
app.post("/api/v1/register", upload.single("faceImg"), async (req, res) => {
  try {
    const { nidNumber, password } = req.body;
    const faceFile = req.file;

    if (!nidNumber || !password || !faceFile) {
      return res.status(400).json({ ok: false, error: "Missing fields" });
    }

    console.log("\n=== REGISTRATION START (ZK-SNARK) ===");

    // 1. Hash NID (for QR storage only, not blockchain)
    const nidHash = hashNidNumber(nidNumber);
    console.log("NID Hash:", nidHash);

    // 2. Get embedding from Python FaceNet service
    const embedding = await getFaceEmbedding(faceFile);
    console.log("Embedding dimension:", embedding.length);

    // 3. Generate random salt
    const salt = crypto.randomBytes(16).toString("hex");

    // 4. Compute SNARK-compatible registration data
    //    - Poseidon hash of embedding
    //    - Baby Jubjub public key S = k * G
    const regData = await snark.computeRegistrationData(embedding, salt);
    console.log("✅ SNARK registration data computed");
    console.log("  Poseidon faceHash:", regData.faceHash.toString().slice(0, 20) + "...");
    console.log("  Baby Jubjub Sx:", regData.Sx.toString().slice(0, 20) + "...");
    console.log("  Baby Jubjub Sy:", regData.Sy.toString().slice(0, 20) + "...");

    // 5. Also derive secp256k1 key for LRS (ring signature — stays outside circuit)
    const faceHashSha = sha256Hash(JSON.stringify(embedding));
    const k_lrs = deriveK(faceHashSha, salt);
    const S_lrs = ec.g.mul(k_lrs);
    const Sx_lrs = S_lrs.getX().toString(16);
    const Sy_lrs = S_lrs.getY().toString(16);
    console.log("  secp256k1 LRS key Sx:", Sx_lrs.slice(0, 20) + "...");

    // 6. Register secp256k1 public key on blockchain (for LRS ring)
    await fabricClient.registerUser(nidHash, Sx_lrs, Sy_lrs, salt);
    console.log("✅ Registered in global ring (secp256k1 for LRS)");

    // 7. QR payload — store everything needed for voting
    const qrPayload = {
      nidHash,
      faceHash: faceHashSha,                          // SHA-256 for LRS key derivation
      poseidonFaceHash: regData.faceHash.toString(),   // Poseidon for SNARK
      bjjSx: regData.Sx.toString(),                    // Baby Jubjub public key
      bjjSy: regData.Sy.toString(),                    // Baby Jubjub public key
      salt,
      faceEmbedding: embedding
    };

    // 8. Encrypt
    const encrypted = encryptPayload(qrPayload, password);

    // 9. Generate QR
    const qrBuffer = await QRCode.toBuffer(JSON.stringify(encrypted), {
      errorCorrectionLevel: "L"
    });

    console.log("=== REGISTRATION COMPLETE (ZK-SNARK) ===\n");

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Content-Disposition", "attachment; filename=voter-credential.png");
    res.send(qrBuffer);

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------------------
// LOGIN - ZK-SNARK Proof
// Replaces Schnorr ZKP with PLONK proof
// Proves: Poseidon hash match + Baby Jubjub
// key ownership + face similarity
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

      console.log("\n=== LOGIN ZK-SNARK PROOF START ===");

      // 1. Decode & Decrypt QR
      const encrypted = await decodeQRCode(qrFile);
      const qrData = decryptPayload(encrypted, password);
      console.log("✅ QR decrypted");

      // 2. Get live face embedding
      const faceLogin = await getFaceEmbedding(faceFile);
      console.log("✅ Login face embedding extracted");

      // 3. Check face embedding exists in QR
      const registeredEmbedding = qrData.faceEmbedding;
      if (!registeredEmbedding) {
        throw new Error("No face embedding found in QR code");
      }

      // 4. Check Poseidon face hash exists (SNARK-registered user)
      if (!qrData.poseidonFaceHash || !qrData.bjjSx || !qrData.bjjSy) {
        throw new Error("QR code is from legacy registration. Please re-register with ZK-SNARK.");
      }

      // 5. Generate ZK-SNARK proof
      //    This proves inside the circuit:
      //    - Poseidon(embedding || salt) == faceHash
      //    - S = k * G on Baby Jubjub
      //    - squared_cosine(live, registered) >= threshold
      const { proof, publicSignals, isValid } = await snark.generateAuthProof(
        faceLogin,
        registeredEmbedding,
        qrData.salt,
        BigInt(qrData.poseidonFaceHash),
        BigInt(qrData.bjjSx),
        BigInt(qrData.bjjSy)
      );

      if (!isValid) {
        return res.json({
          ok: false,
          error: "ZK-SNARK proof verification failed — biometric mismatch or tampering detected",
          isMatch: false
        });
      }

      console.log("✅ ZK-SNARK proof generated and verified");
      console.log("=== LOGIN ZK-SNARK PROOF COMPLETE ===\n");

      res.json({
        ok: true,
        isMatch: true,
        snarkProof: {
          proof,
          publicSignals,
          protocol: "plonk",
          curve: "bn128"
        },
        nidHash: qrData.nidHash
      });

    } catch (err) {
      console.error("LOGIN SNARK ERROR:", err);
      res.status(500).json({ ok: false, error: err.message });
    }
  }
);

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
      zkp: "zk-snark (PLONK, Poseidon, Baby Jubjub)",
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
    // Initialize SNARK Poseidon (warm up circomlibjs)
    console.log("⏳ Initializing ZK-SNARK primitives...");
    await snark.initPoseidon();
    console.log("✅ Poseidon hash initialized");

    await fabricClient.connect();
    app.listen(PORT, () => {
      console.log(`🚀 Anonymous Voting Server running on http://localhost:${PORT}`);
      console.log(`🔐 ZKP: zk-SNARK (Circom 2 + SnarkJS + PLONK)`);
      console.log(`   Hash: Poseidon (SNARK-friendly)`);
      console.log(`   ECC:  Baby Jubjub (in-circuit) + secp256k1 (LRS)`);
      console.log(`📊 Endpoints:`);
      console.log(`   POST /api/v1/register - Register voter (SNARK + LRS keys)`);
      console.log(`   POST /api/v1/login/challenge - ZK-SNARK auth proof`);
      console.log(`   POST /api/v1/ballot/create - Create ballot`);
      console.log(`   POST /api/v1/tally/setup/:ballotId - Setup homomorphic encryption`);
      console.log(`   POST /api/v1/vote - Cast anonymous vote (SNARK + LRS)`);
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
