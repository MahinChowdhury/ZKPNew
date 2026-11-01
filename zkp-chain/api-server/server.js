// ============================
// Imports & Setup
// ============================
const express = require("express");
const cors = require("cors");
const path = require("path");
const FabricClient = require("./fabric-client");
const registerRoutes = require("./routes/register");
const voteRoutes = require("./routes/vote");
const ballotRoutes = require("./routes/ballot");
const tallyRoutes = require("./routes/tally");
const snark = require("./crypto/snark");
const irisSnark = require("./crypto/iris-snark");

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
app.use(express.json({ limit: "1mb" }));

// Shared dependencies for the route modules
app.use((req, res, next) => {
  res.locals.fabricClient = fabricClient;
  res.locals.ballotRoutes = ballotRoutes;
  res.locals.tallyRoutes = tallyRoutes;
  res.locals.snark = snark;
  res.locals.irisSnark = irisSnark;
  next();
});

// ============================
// Circuit artifacts for client-side proving
// (public by design: the proving key reveals nothing about any voter)
// ============================
const CIRCUITS_DIR = path.join(__dirname, "circuits");
const CIRCUIT_ARTIFACTS = {
  "face_auth.wasm": path.join(CIRCUITS_DIR, "face_auth_js", "face_auth.wasm"),
  "face_auth.zkey": path.join(CIRCUITS_DIR, "face_auth.zkey"),
  "iris_auth.wasm": path.join(CIRCUITS_DIR, "iris_auth_js", "iris_auth.wasm"),
  "iris_auth.zkey": path.join(CIRCUITS_DIR, "iris_auth.zkey"),
  "enroll_auth.wasm": path.join(CIRCUITS_DIR, "enroll_auth_js", "enroll_auth.wasm"),
  "enroll_auth.zkey": path.join(CIRCUITS_DIR, "enroll_auth.zkey"),
};
app.get("/circuits/:file", (req, res) => {
  const file = CIRCUIT_ARTIFACTS[req.params.file];
  if (!file) return res.status(404).end();
  res.sendFile(file, { maxAge: "1h" });
});

// ============================
// Routes
// ============================

// RA enrolment: receives (NID, commitment) only
app.use("/api/v1/register", registerRoutes);

// Authorised capture-device registry (sensor attestation)
app.use("/api/v1/sensors", require("./routes/sensors"));

// Mount ballot routes
app.use("/api/v1/ballot", ballotRoutes);

// Mount tally routes
app.use("/api/v1/tally", tallyRoutes);

// Vote relay: receives (proof, nullifier, ciphertexts) only
app.use("/api/v1/vote", voteRoutes);

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
      console.log(`   POST /api/v1/register - RA enrolment of a client-built commitment (NID, commitment)`);
      console.log(`   POST /api/v1/ballot/create - Create ballot`);
      console.log(`   POST /api/v1/tally/setup/:ballotId - Setup homomorphic encryption`);
      console.log(`   POST /api/v1/vote - Relay a client-built vote (proof, nullifier, ciphertexts)`);
      console.log(`   GET  /api/v1/ballot/:ballotId/chain - On-chain ballot key for client encryption`);
      console.log(`   GET  /circuits/{face,iris,enroll}_auth.{wasm,zkey} - Artifacts for client-side proving`);
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
