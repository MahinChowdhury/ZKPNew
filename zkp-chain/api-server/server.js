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
const FabricClient = require("./fabric-client");
const voteRoutes = require("./routes/vote");
const ballotRoutes = require("./routes/ballot");
const tallyRoutes = require("./routes/tally");
const snark = require("./crypto/snark");
const irisSnark = require("./crypto/iris-snark");
const credentialStore = require("./credential-store");

require("dotenv").config();

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

// ============================
// External Python API — FACE
// ============================

async function getFaceEmbedding(file) {
  const form = new FormData();
  form.append("file", file.buffer, {
    filename: file.originalname,
    contentType: file.mimetype,
  });

  const res = await axios.post("http://localhost:8000/face/get-embedding", form, {
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

  const res = await axios.post("http://localhost:8000/face/compare-embeddings", {
    face_login: faceLogin,
    face_reg: faceReg,
  });

  console.log("Comparison result:", res.data);
  return res.data.is_same_person;
}

// ============================
// External Python API — IRIS
// ============================

async function getIrisCode(file) {
  const form = new FormData();
  form.append("file", file.buffer, {
    filename: file.originalname,
    contentType: file.mimetype,
  });

  const res = await axios.post("http://localhost:8000/iris/get-iriscode", form, {
    headers: form.getHeaders(),
  });

  if (!res.data || !res.data.iris_code) {
    throw new Error("Python API did not return iris code");
  }

  return {
    irisCode: res.data.iris_code,
    noiseMask: res.data.noise_mask,
    dimension: res.data.dimension,
    quality: res.data.quality,
  };
}

async function compareIrisCodes(irisCodeLogin, noiseMaskLogin, irisCodeReg, noiseMaskReg) {
  console.log("Comparing iris codes...");
  console.log("Login iris code length:", irisCodeLogin.length);
  console.log("Registered iris code length:", irisCodeReg.length);

  const res = await axios.post("http://localhost:8000/iris/compare-iriscodes", {
    iris_code_login: irisCodeLogin,
    noise_mask_login: noiseMaskLogin,
    iris_code_reg: irisCodeReg,
    noise_mask_reg: noiseMaskReg,
  });

  console.log("Iris comparison result:", res.data);
  return res.data;
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
  res.locals.getIrisCode = getIrisCode;
  res.locals.compareIrisCodes = compareIrisCodes;
  res.locals.ballotRoutes = ballotRoutes;
  res.locals.tallyRoutes = tallyRoutes;
  res.locals.snark = snark;
  res.locals.irisSnark = irisSnark;
  res.locals.credentialStore = credentialStore;
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
// REGISTER (Face or Iris — independent)
// Uses ZK-SNARK (Poseidon + Merkle Tree)
// biometricMode: "face" (default) | "iris"
// Each mode uses its own Merkle tree
// --------------------------------------
app.post("/api/v1/register", upload.fields([
  { name: "faceImg", maxCount: 1 },
  { name: "irisImg", maxCount: 1 },
]), async (req, res) => {
  try {
    const { nidNumber, password, biometricMode } = req.body;
    const mode = biometricMode || "face";

    const faceFile = req.files?.faceImg?.[0];
    const irisFile = req.files?.irisImg?.[0];

    if (!nidNumber || !password) {
      return res.status(400).json({ ok: false, error: "Missing nidNumber or password" });
    }

    if (mode === "face" && !faceFile) {
      return res.status(400).json({ ok: false, error: "Missing faceImg for face biometric mode" });
    }

    if (mode === "iris" && !irisFile) {
      return res.status(400).json({ ok: false, error: "Missing irisImg for iris biometric mode" });
    }

    console.log(`\n=== REGISTRATION START (${mode.toUpperCase()} — Merkle + Nullifier) ===`);

    // 1. Hash NID
    const nidHash = hashNidNumber(nidNumber);
    console.log("NID Hash:", nidHash);

    // 2. Generate random salt
    const salt = crypto.randomBytes(16).toString("hex");

    if (mode === "face") {
      // =====================
      // FACE REGISTRATION
      // =====================
      const embedding = await getFaceEmbedding(faceFile);
      console.log("Face embedding dimension:", embedding.length);

      // Compute SNARK-compatible registration data
      const regData = await snark.computeRegistrationData(embedding, salt);
      console.log("✅ Face SNARK registration data computed");
      console.log("  Poseidon faceHash:", regData.faceHash.toString().slice(0, 20) + "...");
      console.log("  Commitment:", regData.commitment.toString().slice(0, 20) + "...");

      // Register commitment on blockchain (face Merkle tree)
      await fabricClient.registerUser(nidHash, regData.commitment.toString());
      console.log("✅ Face commitment registered on blockchain");

      // Invalidate face Merkle tree cache
      snark.invalidateMerkleCache();

      // Save SNARK credentials to encrypted store (face)
      const snarkCredentials = {
        poseidonFaceHash: regData.faceHash.toString(),
        secretKey: regData.secretKey.toString(),
        commitment: regData.commitment.toString(),
      };
      credentialStore.saveCredentials(nidHash, snarkCredentials, password);
      console.log("✅ Face SNARK credentials saved to encrypted credential store");

      // QR payload (lightweight)
      const qrPayload = {
        nidHash,
        salt,
        biometricMode: "face",
        faceEmbedding: embedding,
      };

      // Encrypt & generate QR
      const encrypted = encryptPayload(qrPayload, password);
      const encryptedStr = JSON.stringify(encrypted);

      const qrBuffer = await QRCode.toBuffer(encryptedStr, {
        errorCorrectionLevel: "L",
      });

      console.log(`📏 QR payload size: ${encryptedStr.length} bytes`);
      console.log(`=== REGISTRATION COMPLETE (FACE — Merkle + Nullifier) ===\n`);

      res.setHeader("Content-Type", "image/png");
      res.setHeader("Content-Disposition", "attachment; filename=voter-credential.png");
      res.send(qrBuffer);

    } else if (mode === "iris") {
      // =====================
      // IRIS REGISTRATION
      // =====================
      const irisResult = await getIrisCode(irisFile);
      console.log("Iris code dimension:", irisResult.dimension);
      console.log("Iris detection quality:", irisResult.quality);

      // Compute SNARK-compatible iris registration data
      // Internally downsamples 196K bits → 256 bits
      const regData = await irisSnark.computeIrisRegistrationData(
        irisResult.irisCode,
        irisResult.noiseMask,
        salt
      );
      console.log("✅ Iris SNARK registration data computed");
      console.log("  Poseidon irisHash:", regData.irisHash.toString().slice(0, 20) + "...");
      console.log("  Commitment:", regData.commitment.toString().slice(0, 20) + "...");

      // Register commitment on blockchain (IRIS Merkle tree — independent)
      await fabricClient.registerIrisUser(nidHash, regData.commitment.toString());
      console.log("✅ Iris commitment registered on blockchain (independent Merkle tree)");

      // Invalidate iris Merkle tree cache
      irisSnark.invalidateIrisMerkleCache();

      // Save iris SNARK credentials to encrypted store (with _iris suffix)
      const irisCredentials = {
        poseidonIrisHash: regData.irisHash.toString(),
        secretKey: regData.secretKey.toString(),
        commitment: regData.commitment.toString(),
        irisCode256: regData.irisCode256,
      };
      credentialStore.saveCredentials(nidHash, irisCredentials, password, "_iris");
      console.log("✅ Iris SNARK credentials saved to encrypted credential store");

      // QR payload (lightweight — no full iris code, just metadata)
      const qrPayload = {
        nidHash,
        salt,
        biometricMode: "iris",
        irisQuality: irisResult.quality,
      };

      // Encrypt & generate QR
      const encrypted = encryptPayload(qrPayload, password);
      const encryptedStr = JSON.stringify(encrypted);

      const qrBuffer = await QRCode.toBuffer(encryptedStr, {
        errorCorrectionLevel: "L",
      });

      console.log(`📏 QR payload size: ${encryptedStr.length} bytes`);
      console.log(`=== REGISTRATION COMPLETE (IRIS — Merkle + Nullifier) ===\n`);

      res.setHeader("Content-Type", "image/png");
      res.setHeader("Content-Disposition", "attachment; filename=voter-credential-iris.png");
      res.send(qrBuffer);

    } else {
      return res.status(400).json({ ok: false, error: `Invalid biometricMode: ${mode}. Must be "face" or "iris".` });
    }

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------------------------------------
// LOGIN - ZK-SNARK Proof (Face or Iris)
// biometricMode: "face" (default) | "iris"
// Each mode uses its own Merkle tree
// --------------------------------------
app.post(
  "/api/v1/login/challenge",
  upload.fields([{ name: "qrCode" }, { name: "faceImg" }, { name: "irisImg" }]),
  async (req, res) => {
    try {
      const { password, biometricMode } = req.body;
      const mode = biometricMode || "face";

      const qrFile = req.files.qrCode?.[0];
      const faceFile = req.files.faceImg?.[0];
      const irisFile = req.files.irisImg?.[0];

      if (!password || !qrFile) {
        return res.status(400).json({ ok: false, error: "Missing password or qrCode" });
      }

      if (mode === "face" && !faceFile) {
        return res.status(400).json({ ok: false, error: "Missing faceImg for face biometric mode" });
      }

      if (mode === "iris" && !irisFile) {
        return res.status(400).json({ ok: false, error: "Missing irisImg for iris biometric mode" });
      }

      console.log(`\n=== LOGIN ZK-SNARK PROOF START (${mode.toUpperCase()} — Merkle + Nullifier) ===`);

      // 1. Decode & Decrypt QR
      const encrypted = await decodeQRCode(qrFile);
      const qrData = decryptPayload(encrypted, password);
      console.log("✅ QR decrypted");
      console.log("  QR biometric mode:", qrData.biometricMode || "face");

      // Verify the QR's biometric mode matches the request
      const qrMode = qrData.biometricMode || "face";
      if (qrMode !== mode) {
        return res.status(400).json({
          ok: false,
          error: `QR code was registered with "${qrMode}" biometric but login mode is "${mode}". Please use the correct mode.`,
        });
      }

      // Use a dummy electionId for login (not election-specific)
      const loginElectionId = BigInt("0");

      if (mode === "face") {
        // =====================
        // FACE LOGIN
        // =====================

        // Load face SNARK credentials
        const snarkCreds = credentialStore.loadCredentials(qrData.nidHash, password);
        console.log("✅ Face SNARK credentials loaded from credential store");

        // Get live face embedding
        const faceLogin = await getFaceEmbedding(faceFile);
        console.log("✅ Login face embedding extracted");

        // Check face embedding exists in QR
        const registeredEmbedding = qrData.faceEmbedding;
        if (!registeredEmbedding) {
          throw new Error("No face embedding found in QR code");
        }

        // Get all face commitments from blockchain
        const commitments = await fabricClient.getCommitments();
        const commitmentsBigInt = commitments.map((c) => BigInt(c));

        // Generate ZK-SNARK proof (face)
        const { proof, publicSignals, isValid } = await snark.generateAuthProof(
          faceLogin,
          registeredEmbedding,
          qrData.salt,
          BigInt(snarkCreds.poseidonFaceHash),
          BigInt(snarkCreds.secretKey),
          commitmentsBigInt,
          loginElectionId
        );

        if (!isValid) {
          return res.json({
            ok: false,
            error: "ZK-SNARK proof verification failed — face biometric mismatch or tampering detected",
            isMatch: false,
          });
        }

        console.log("✅ Face ZK-SNARK proof generated and verified");
        console.log("=== LOGIN ZK-SNARK PROOF COMPLETE (FACE) ===\n");

        res.json({
          ok: true,
          isMatch: true,
          biometricMode: "face",
          snarkProof: {
            proof,
            publicSignals,
            protocol: "groth16",
            curve: "bn128",
          },
          nidHash: qrData.nidHash,
        });

      } else if (mode === "iris") {
        // =====================
        // IRIS LOGIN
        // =====================

        // Load iris SNARK credentials
        const irisCreds = credentialStore.loadCredentials(qrData.nidHash, password, "_iris");
        console.log("✅ Iris SNARK credentials loaded from credential store");

        // Get live iris code from Python
        const liveIrisResult = await getIrisCode(irisFile);
        console.log("✅ Login iris code extracted (quality:", liveIrisResult.quality, ")");

        // Get registered downsampled iris code from credentials
        const registeredIrisCode256 = irisCreds.irisCode256;
        if (!registeredIrisCode256) {
          throw new Error("No iris code found in credential store");
        }

        // Get all iris commitments from blockchain (independent Merkle tree)
        const irisCommitments = await fabricClient.getIrisCommitments();
        const irisCommitmentsBigInt = irisCommitments.map((c) => BigInt(c));

        // Generate ZK-SNARK proof (iris)
        const { proof, publicSignals, isValid } = await irisSnark.generateIrisAuthProof(
          liveIrisResult.irisCode,
          liveIrisResult.noiseMask,
          registeredIrisCode256,
          qrData.salt,
          BigInt(irisCreds.poseidonIrisHash),
          BigInt(irisCreds.secretKey),
          irisCommitmentsBigInt,
          loginElectionId
        );

        if (!isValid) {
          return res.json({
            ok: false,
            error: "ZK-SNARK proof verification failed — iris biometric mismatch or tampering detected",
            isMatch: false,
          });
        }

        console.log("✅ Iris ZK-SNARK proof generated and verified");
        console.log("=== LOGIN ZK-SNARK PROOF COMPLETE (IRIS) ===\n");

        res.json({
          ok: true,
          isMatch: true,
          biometricMode: "iris",
          snarkProof: {
            proof,
            publicSignals,
            protocol: "groth16",
            curve: "bn128",
          },
          nidHash: qrData.nidHash,
        });

      } else {
        return res.status(400).json({ ok: false, error: `Invalid biometricMode: ${mode}` });
      }

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
    const voterCount = await fabricClient.getVoterCount();
    const irisVoterCount = await fabricClient.getIrisVoterCount();
    const voteCount = await fabricClient.getVoteCount();

    res.json({
      ok: true,
      status: "healthy",
      blockchain: "connected",
      system: "anonymous-voting",
      zkp: "zk-snark (Groth16, Poseidon, Merkle Tree + Nullifier)",
      biometricModes: ["face", "iris"],
      registeredVoters: {
        face: voterCount,
        iris: irisVoterCount,
        total: voterCount + irisVoterCount,
      },
      totalVotes: voteCount,
    });
  } catch (err) {
    res.status(503).json({
      ok: false,
      status: "unhealthy",
      error: err.message,
    });
  }
});

app.get("/api/v1/commitments", async (req, res) => {
  try {
    const commitments = await fabricClient.getCommitments();
    res.json({
      ok: true,
      biometricMode: "face",
      voterCount: commitments.length,
      commitments,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/commitments/iris", async (req, res) => {
  try {
    const commitments = await fabricClient.getIrisCommitments();
    res.json({
      ok: true,
      biometricMode: "iris",
      voterCount: commitments.length,
      commitments,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/commitments/count", async (req, res) => {
  try {
    const faceCount = await fabricClient.getVoterCount();
    const irisCount = await fabricClient.getIrisVoterCount();
    res.json({ ok: true, face: faceCount, iris: irisCount, total: faceCount + irisCount });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Legacy endpoints (for backward compatibility)
app.get("/api/v1/ring", async (req, res) => {
  try {
    const commitments = await fabricClient.getCommitments();
    res.json({
      ok: true,
      ringSize: commitments.length,
      note: "This endpoint is deprecated - use /api/v1/commitments. Ring replaced by Merkle tree commitments.",
      ring: commitments.map((c, i) => ({ index: i, commitment: c })),
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/ring/size", async (req, res) => {
  try {
    const count = await fabricClient.getVoterCount();
    res.json({
      ok: true,
      ringSize: count,
      note: "This endpoint is deprecated - use /api/v1/commitments/count",
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/identities", async (req, res) => {
  try {
    const commitments = await fabricClient.getCommitments();
    res.json({
      ok: true,
      count: commitments.length,
      note: "This endpoint is deprecated - use /api/v1/commitments",
      identities: commitments.map((_, i) => `voter_${i}`),
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/v1/identities/count", async (req, res) => {
  try {
    const count = await fabricClient.getVoterCount();
    res.json({
      ok: true,
      count,
      note: "This endpoint is deprecated - use /api/v1/commitments/count",
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
    // Initialize SNARK Poseidon (warm up circomlibjs — shared by face & iris)
    console.log("⏳ Initializing ZK-SNARK primitives...");
    await snark.initPoseidon();
    console.log("✅ Poseidon hash initialized");

    // Pre-warm face Merkle zero hashes
    await snark.getZeroHashes();
    console.log("✅ Face Merkle zero hashes pre-computed");

    // Pre-warm iris Merkle zero hashes (independent tree)
    await irisSnark.getIrisZeroHashes();
    console.log("✅ Iris Merkle zero hashes pre-computed");

    await fabricClient.connect();
    app.listen(PORT, () => {
      console.log(`🚀 Anonymous Voting Server running on http://localhost:${PORT}`);
      console.log(`🔐 ZKP: zk-SNARK (Circom 2 + SnarkJS + Groth16)`);
      console.log(`   Hash: Poseidon (SNARK-friendly)`);
      console.log(`   Face Anonymity: Merkle Tree (depth ${snark.MERKLE_TREE_LEVELS})`);
      console.log(`   Iris Anonymity: Merkle Tree (depth ${irisSnark.MERKLE_TREE_LEVELS}) — independent`);
      console.log(`   Anti-replay: Nullifier = Poseidon(secretKey, electionId)`);
      console.log(`   Biometric Modes: face (cosine similarity), iris (Hamming distance)`);
      console.log(`📊 Endpoints:`);
      console.log(`   POST /api/v1/register - Register voter (face or iris, biometricMode param)`);
      console.log(`   POST /api/v1/login/challenge - ZK-SNARK auth proof (face or iris)`);
      console.log(`   POST /api/v1/ballot/create - Create ballot`);
      console.log(`   POST /api/v1/tally/setup/:ballotId - Setup homomorphic encryption`);
      console.log(`   POST /api/v1/vote - Cast anonymous vote (face or iris SNARK)`);
      console.log(`   POST /api/v1/tally/compute/:ballotId - Compute homomorphic tally`);
      console.log(`   GET  /api/v1/vote/results - Get vote results`);
      console.log(`   GET  /api/v1/commitments - Get face voter commitments`);
      console.log(`   GET  /api/v1/commitments/iris - Get iris voter commitments`);
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
