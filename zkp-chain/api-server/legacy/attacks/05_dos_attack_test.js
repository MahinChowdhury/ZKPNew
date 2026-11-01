/**
 * ═══════════════════════════════════════════════════════════════════
 *  Category 5 — Network-Level (DoS) Attack Tests
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Tests the system's resilience under network-level attacks.
 *  ⚠️  LIVE SYSTEM TESTS — Requires API server running on port 3000.
 *
 *  Tests:
 *    5.1  DoS flood with malformed payloads (varying scale)
 *    5.2  Valid-looking but semantically invalid requests
 *    5.3  Large payload resource exhaustion
 *    5.4  Unauthorized endpoint access (private key exposure)
 *    5.5  Server recovery after flood
 *
 *  Run: node attacks/05_dos_attack_test.js
 *  Requires: API server running on localhost:3000
 */

"use strict";

const {
  nowMs,
  printHeader, printSubHeader, printResult, printTable,
  saveResults, mean, stddev, percentile
} = require("./utils");

let axios;
try {
  axios = require("axios");
} catch (e) {
  console.error("axios not found. Run: npm install axios");
  process.exit(1);
}

let FormData;
try {
  FormData = require("form-data");
} catch (e) {
  console.error("form-data not found. Run: npm install form-data");
  process.exit(1);
}

const API_URL = process.env.API_URL || "http://localhost:3000";

async function run() {
  printHeader("Category 5 — Network-Level (DoS) Attack Tests (Live API)");

  const results = {
    category: "Network-Level DoS",
    timestamp: new Date().toISOString(),
    requires_live_system: true,
    tests: {}
  };

  // Check if server is up
  try {
    await axios.get(`${API_URL}/api/v1/health`, { timeout: 3000 });
    console.log("  ✅ API server is reachable\n");
  } catch (e) {
    console.error("  ❌ API server not reachable at " + API_URL);
    console.error("     Start the server: cd api-server && node server.js");
    results.error = "API server not reachable";
    saveResults("05_dos_attack_results.json", results);
    return results;
  }

  // ─── 5.1  DoS Flood with Malformed Payloads ────────────────────
  printSubHeader("5.1  DoS Flood — Malformed Payloads at Various Scales");

  const FLOOD_LEVELS = [50, 100, 250, 500];
  const floodResults = [];

  for (const count of FLOOD_LEVELS) {
    let rejections = 0;
    let serverErrors = 0;
    let timeouts = 0;
    const responseTimes = [];

    const startTime = nowMs();
    const promises = [];

    for (let i = 0; i < count; i++) {
      const form = new FormData();
      // Intentionally missing required fields
      form.append("voteChoice", "MaliciousCandidate_" + i);

      const t0 = nowMs();
      promises.push(
        axios.post(`${API_URL}/api/v1/vote`, form, {
          headers: form.getHeaders(),
          timeout: 5000
        })
        .then(() => {
          responseTimes.push(nowMs() - t0);
          serverErrors++; // Shouldn't succeed
        })
        .catch((err) => {
          responseTimes.push(nowMs() - t0);
          if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT") {
            timeouts++;
          } else if (err.response && err.response.status >= 400 && err.response.status < 500) {
            rejections++; // Correctly rejected
          } else {
            serverErrors++;
          }
        })
      );
    }

    await Promise.allSettled(promises);
    const duration = nowMs() - startTime;

    const entry = {
      requests: count,
      correctly_rejected: rejections,
      server_errors: serverErrors,
      timeouts: timeouts,
      duration_ms: duration.toFixed(0),
      rejection_rate: ((rejections / count) * 100).toFixed(1) + "%",
      response_time_mean_ms: responseTimes.length > 0 ? mean(responseTimes).toFixed(1) : "N/A",
      response_time_p95_ms: responseTimes.length > 0 ? percentile(responseTimes, 95).toFixed(1) : "N/A",
      response_time_p99_ms: responseTimes.length > 0 ? percentile(responseTimes, 99).toFixed(1) : "N/A",
      pass: rejections + timeouts > 0 && serverErrors === 0
    };
    floodResults.push(entry);

    printResult(
      `${count} requests`,
      `rejected=${rejections}, err=${serverErrors}, timeout=${timeouts}, P95=${entry.response_time_p95_ms}ms`,
      entry.pass
    );
  }

  results.tests["5.1_malformed_flood"] = {
    levels: FLOOD_LEVELS,
    results: floodResults,
    pass: floodResults.every(r => r.pass)
  };

  // ─── 5.2  Valid-Looking But Invalid Requests ───────────────────
  printSubHeader("5.2  Valid-Looking Requests (Correct Structure, Bad Data)");

  const VALID_LOOKING_COUNT = 100;
  let validLookingRejections = 0;
  let validLookingErrors = 0;
  const validLookingTimes = [];

  const crypto = require("crypto");
  const promises52 = [];

  for (let i = 0; i < VALID_LOOKING_COUNT; i++) {
    const form = new FormData();
    // Create a fake "QR code" (random bytes as image)
    const fakeQR = crypto.randomBytes(1024);
    form.append("qrCode", fakeQR, { filename: "qr.png", contentType: "image/png" });
    // Create a fake "face image"
    const fakeFace = crypto.randomBytes(2048);
    form.append("faceImg", fakeFace, { filename: "face.jpg", contentType: "image/jpeg" });
    form.append("password", "fakepassword123");
    form.append("voteChoice", "CandidateA");

    const t0 = nowMs();
    promises52.push(
      axios.post(`${API_URL}/api/v1/vote`, form, {
        headers: form.getHeaders(),
        timeout: 10000
      })
      .then(() => {
        validLookingTimes.push(nowMs() - t0);
        validLookingErrors++; // Should not succeed
      })
      .catch((err) => {
        validLookingTimes.push(nowMs() - t0);
        if (err.response && err.response.status >= 400) {
          validLookingRejections++;
        } else {
          validLookingErrors++;
        }
      })
    );
  }

  await Promise.allSettled(promises52);

  results.tests["5.2_valid_looking_flood"] = {
    requests: VALID_LOOKING_COUNT,
    rejected: validLookingRejections,
    errors: validLookingErrors,
    rejection_rate: ((validLookingRejections / VALID_LOOKING_COUNT) * 100).toFixed(1) + "%",
    response_time_mean_ms: validLookingTimes.length > 0 ? mean(validLookingTimes).toFixed(1) : "N/A",
    response_time_p95_ms: validLookingTimes.length > 0 ? percentile(validLookingTimes, 95).toFixed(1) : "N/A",
    pass: validLookingRejections === VALID_LOOKING_COUNT
  };

  printResult(
    `Valid-looking requests rejected`,
    `${validLookingRejections}/${VALID_LOOKING_COUNT}`,
    validLookingRejections === VALID_LOOKING_COUNT
  );

  // ─── 5.3  Large Payload Resource Exhaustion ────────────────────
  printSubHeader("5.3  Large Payload Attack");

  const PAYLOAD_SIZES = [1, 5, 10, 50]; // MB
  const payloadResults = [];

  for (const sizeMB of PAYLOAD_SIZES) {
    const form = new FormData();
    const largeBuffer = Buffer.alloc(sizeMB * 1024 * 1024, 0x42);
    form.append("qrCode", largeBuffer, { filename: "big.png", contentType: "image/png" });
    form.append("password", "test");
    form.append("voteChoice", "X");

    let responseStatus = "unknown";
    let responseTime = 0;

    try {
      const t0 = nowMs();
      await axios.post(`${API_URL}/api/v1/vote`, form, {
        headers: form.getHeaders(),
        timeout: 15000,
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      });
      responseTime = nowMs() - t0;
      responseStatus = "accepted (bad)";
    } catch (err) {
      responseTime = nowMs();
      if (err.response) {
        responseStatus = `HTTP ${err.response.status}`;
      } else if (err.code === "ECONNABORTED") {
        responseStatus = "timeout";
      } else if (err.code === "ERR_FR_MAX_BODY_LENGTH_EXCEEDED" || err.code === "ECONNRESET") {
        responseStatus = "connection reset";
      } else {
        responseStatus = err.code || err.message;
      }
    }

    const entry = {
      size_mb: sizeMB,
      response: responseStatus,
      no_crash: responseStatus !== "accepted (bad)"
    };
    payloadResults.push(entry);

    printResult(`${sizeMB}MB payload`, responseStatus, entry.no_crash);
  }

  results.tests["5.3_large_payload"] = {
    sizes_mb: PAYLOAD_SIZES,
    results: payloadResults,
    pass: payloadResults.every(r => r.no_crash)
  };

  // ─── 5.4  Unauthorized Endpoint Access ─────────────────────────
  printSubHeader("5.4  Unauthorized Endpoint Access — Private Key Exposure");

  let keysExposed = false;
  let keysResponse = null;

  try {
    const resp = await axios.get(`${API_URL}/api/v1/tally/keys`, { timeout: 5000 });
    keysResponse = resp.data;
    keysExposed = resp.data && resp.data.ok === true;
  } catch (e) {
    keysExposed = false;
  }

  results.tests["5.4_unauthorized_access"] = {
    endpoint: "/api/v1/tally/keys",
    keys_exposed_without_auth: keysExposed,
    keys_count: keysResponse ? keysResponse.count : 0,
    vulnerability: keysExposed
      ? "CRITICAL — ElGamal private keys accessible without authentication"
      : "Endpoint not accessible or no keys stored",
    pass: !keysExposed || (keysResponse && keysResponse.count === 0)
  };

  printResult("Private keys endpoint accessible", keysExposed, !keysExposed);
  if (keysExposed && keysResponse.count > 0) {
    console.log("  🚨 CRITICAL: ElGamal private keys are exposed without authentication!");
    console.log("  → Fix: Add authentication to /api/v1/tally/keys or remove the endpoint");
  }

  // ─── 5.5  Server Recovery After Flood ──────────────────────────
  printSubHeader("5.5  Server Recovery After Flood");

  // Wait a moment, then check if server is still responsive
  await new Promise(resolve => setTimeout(resolve, 1000));

  let serverHealthy = false;
  let recoveryTime = 0;

  const recoveryStart = nowMs();
  try {
    const healthResp = await axios.get(`${API_URL}/api/v1/health`, { timeout: 5000 });
    serverHealthy = healthResp.data && healthResp.data.ok === true;
    recoveryTime = nowMs() - recoveryStart;
  } catch (e) {
    serverHealthy = false;
  }

  results.tests["5.5_server_recovery"] = {
    server_responsive_after_flood: serverHealthy,
    health_check_time_ms: recoveryTime.toFixed(0),
    pass: serverHealthy
  };

  printResult("Server still responsive after all attacks", serverHealthy, serverHealthy);
  printResult("Health check response time", `${recoveryTime.toFixed(0)} ms`);

  // ─── Summary ──────────────────────────────────────────────────
  printSubHeader("Summary");
  const allTests = Object.values(results.tests);
  const passed = allTests.filter(t => t.pass).length;

  printTable([
    ["Test", "Result"],
    ["5.1 Malformed Flood", results.tests["5.1_malformed_flood"].pass ? "PASS" : "FAIL"],
    ["5.2 Valid-Looking Flood", results.tests["5.2_valid_looking_flood"].pass ? "PASS" : "FAIL"],
    ["5.3 Large Payload", results.tests["5.3_large_payload"].pass ? "PASS" : "FAIL"],
    ["5.4 Unauthorized Access", results.tests["5.4_unauthorized_access"].pass ? "PASS/OK" : "VULNERABILITY"],
    ["5.5 Server Recovery", results.tests["5.5_server_recovery"].pass ? "PASS" : "FAIL"],
  ]);

  console.log(`\n  Overall: ${passed}/${allTests.length} tests passed`);

  saveResults("05_dos_attack_results.json", results);
  return results;
}

if (require.main === module) {
  run().catch(console.error);
}
module.exports = { run };
