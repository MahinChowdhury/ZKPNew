// ============================
// Ballot Management Routes
// ============================

const express = require("express");
const router = express.Router();

// In-memory ballot storage (in production, use database)
let activeBallot = null;
const ballotHistory = [];

/**
 * POST /api/v1/ballot/create
 * Create a new ballot/election
 * 
 * Body:
 * {
 *   "title": "Presidential Election 2025",
 *   "description": "Vote for the next president",
 *   "options": ["Alice Johnson", "Bob Smith", "Charlie Davis"],
 *   "startTime": "2025-12-01T00:00:00Z",
 *   "endTime": "2025-12-31T23:59:59Z",
 *   "allowMultipleVotes": false
 * }
 */
router.post("/create", async (req, res) => {
  try {
    const { title, description, options, startTime, endTime, allowMultipleVotes } = req.body;

    // Validation
    if (!title || !options || !Array.isArray(options) || options.length < 2) {
      return res.status(400).json({
        ok: false,
        error: "Invalid ballot data. Need title and at least 2 options"
      });
    }

    // Check for duplicate options
    const uniqueOptions = [...new Set(options)];
    if (uniqueOptions.length !== options.length) {
      return res.status(400).json({
        ok: false,
        error: "Duplicate options detected"
      });
    }

    // Create ballot
    const ballot = {
      id: `ballot_${Date.now()}`,
      title,
      description: description || "",
      options: options.map((opt, idx) => ({
        id: `option_${idx}`,
        name: opt,
        votes: 0
      })),
      startTime: startTime || new Date().toISOString(),
      endTime: endTime || null,
      allowMultipleVotes: allowMultipleVotes || false,
      createdAt: new Date().toISOString(),
      status: "active"
    };

    // Store ballot (close previous if exists)
    if (activeBallot) {
      activeBallot.status = "closed";
      activeBallot.closedAt = new Date().toISOString();
      ballotHistory.push(activeBallot);
    }

    activeBallot = ballot;

    console.log(`✅ Ballot created: ${ballot.title}`);
    console.log(`   Options: ${ballot.options.map(o => o.name).join(", ")}`);

    res.json({
      ok: true,
      ballot: {
        id: ballot.id,
        title: ballot.title,
        description: ballot.description,
        options: ballot.options.map(o => ({ id: o.id, name: o.name })),
        startTime: ballot.startTime,
        endTime: ballot.endTime,
        allowMultipleVotes: ballot.allowMultipleVotes,
        status: ballot.status
      }
    });

  } catch (err) {
    console.error("CREATE BALLOT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/ballot/active
 * Get the current active ballot
 */
router.get("/active", (req, res) => {
  try {
    if (!activeBallot) {
      return res.json({
        ok: true,
        ballot: null,
        message: "No active ballot"
      });
    }

    // Check if ballot has expired
    if (activeBallot.endTime && new Date(activeBallot.endTime) < new Date()) {
      activeBallot.status = "expired";
    }

    res.json({
      ok: true,
      ballot: {
        id: activeBallot.id,
        title: activeBallot.title,
        description: activeBallot.description,
        options: activeBallot.options.map(o => ({ id: o.id, name: o.name })),
        startTime: activeBallot.startTime,
        endTime: activeBallot.endTime,
        allowMultipleVotes: activeBallot.allowMultipleVotes,
        status: activeBallot.status
      }
    });

  } catch (err) {
    console.error("GET ACTIVE BALLOT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/v1/ballot/close
 * Close the active ballot
 */
router.post("/close", (req, res) => {
  try {
    if (!activeBallot) {
      return res.status(404).json({
        ok: false,
        error: "No active ballot to close"
      });
    }

    activeBallot.status = "closed";
    activeBallot.closedAt = new Date().toISOString();
    ballotHistory.push(activeBallot);

    console.log(`🔒 Ballot closed: ${activeBallot.title}`);

    const closedBallot = activeBallot;
    activeBallot = null;

    res.json({
      ok: true,
      message: "Ballot closed successfully",
      ballot: {
        id: closedBallot.id,
        title: closedBallot.title,
        status: closedBallot.status,
        closedAt: closedBallot.closedAt
      }
    });

  } catch (err) {
    console.error("CLOSE BALLOT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/ballot/history
 * Get ballot history
 */
router.get("/history", (req, res) => {
  try {
    res.json({
      ok: true,
      count: ballotHistory.length,
      ballots: ballotHistory.map(b => ({
        id: b.id,
        title: b.title,
        status: b.status,
        createdAt: b.createdAt,
        closedAt: b.closedAt,
        optionsCount: b.options.length
      }))
    });
  } catch (err) {
    console.error("GET HISTORY ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/v1/ballot/:ballotId
 * Get specific ballot by ID
 */
router.get("/:ballotId", (req, res) => {
  try {
    const { ballotId } = req.params;

    // Check active ballot
    if (activeBallot && activeBallot.id === ballotId) {
      return res.json({
        ok: true,
        ballot: activeBallot
      });
    }

    // Check history
    const ballot = ballotHistory.find(b => b.id === ballotId);
    if (!ballot) {
      return res.status(404).json({
        ok: false,
        error: "Ballot not found"
      });
    }

    res.json({
      ok: true,
      ballot
    });

  } catch (err) {
    console.error("GET BALLOT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * DELETE /api/v1/ballot/:ballotId
 * Delete a ballot (admin only - use with caution)
 */
router.delete("/:ballotId", (req, res) => {
  try {
    const { ballotId } = req.params;

    // Check if it's the active ballot
    if (activeBallot && activeBallot.id === ballotId) {
      activeBallot = null;
      return res.json({
        ok: true,
        message: "Active ballot deleted"
      });
    }

    // Check history
    const index = ballotHistory.findIndex(b => b.id === ballotId);
    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "Ballot not found"
      });
    }

    ballotHistory.splice(index, 1);

    res.json({
      ok: true,
      message: "Ballot deleted from history"
    });

  } catch (err) {
    console.error("DELETE BALLOT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Helper function to get active ballot (for vote validation)
router.getActiveBallot = () => activeBallot;

// Helper function to get a ballot by ID (active or from history)
router.getBallotById = (ballotId) => {
  if (activeBallot && activeBallot.id === ballotId) {
    return activeBallot;
  }
  return ballotHistory.find(b => b.id === ballotId) || null;
};

module.exports = router;