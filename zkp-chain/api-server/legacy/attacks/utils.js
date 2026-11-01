"use strict";

const crypto = require("crypto");
const EC = require("elliptic").ec;
const BN = require("bn.js");
const fs = require("fs");
const path = require("path");

const ec = new EC("secp256k1");

// ── Timing ──────────────────────────────────────────────────────────
function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

// ── Console suppression (LRS and homomorphic modules are very verbose) ────
let suppressCount = 0;
const originalConsole = { log: console.log, error: console.error, warn: console.warn };
const originalStderrWrite = process.stderr.write;
const originalStdoutWrite = process.stdout.write;

function suppress(fn) {
  if (suppressCount === 0) {
    console.log = console.error = console.warn = () => {};
    process.stderr.write = () => true;
    process.stdout.write = () => true;
  }
  suppressCount++;
  try { 
    return fn(); 
  } finally { 
    suppressCount--;
    if (suppressCount === 0) {
      Object.assign(console, originalConsole);
      process.stderr.write = originalStderrWrite;
      process.stdout.write = originalStdoutWrite;
    }
  }
}

async function suppressAsync(fn) {
  if (suppressCount === 0) {
    console.log = console.error = console.warn = () => {};
    process.stderr.write = () => true;
    process.stdout.write = () => true;
  }
  suppressCount++;
  try { 
    return await fn(); 
  } finally { 
    suppressCount--;
    if (suppressCount === 0) {
      Object.assign(console, originalConsole);
      process.stderr.write = originalStderrWrite;
      process.stdout.write = originalStdoutWrite;
    }
  }
}

// ── Pretty printing ─────────────────────────────────────────────────
function printHeader(title) {
  console.log("\n" + "═".repeat(70));
  console.log("  " + title);
  console.log("═".repeat(70));
}

function printSubHeader(title) {
  console.log("\n  ── " + title + " ──");
}

function printResult(label, value, pass = null) {
  const icon = pass === null ? "•" : (pass ? "✅" : "❌");
  console.log(`  ${icon} ${label}: ${value}`);
}

function printTable(rows) {
  // rows: array of [col1, col2, col3, ...]
  if (rows.length === 0) return;
  const widths = rows[0].map((_, ci) =>
    Math.max(...rows.map(r => String(r[ci]).length))
  );
  rows.forEach((row, ri) => {
    const line = row.map((c, ci) => String(c).padEnd(widths[ci])).join(" │ ");
    console.log("  " + line);
    if (ri === 0) {
      console.log("  " + widths.map(w => "─".repeat(w)).join("─┼─"));
    }
  });
}

// ── Result saving ───────────────────────────────────────────────────
function saveResults(filename, data) {
  const resultsDir = path.join(__dirname, "results");
  if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });
  const filepath = path.join(resultsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
  console.log(`\n  📁 Saved → attacks/results/${filename}`);
}

// ── Ring generation helpers ─────────────────────────────────────────
function generateRing(size) {
  const keys = Array.from({ length: size }, () => ec.genKeyPair());
  const points = keys.map(k => k.getPublic());
  const data = points.map(p => ({
    x: p.getX().toString(16),
    y: p.getY().toString(16)
  }));
  return { keys, points, data };
}

function signSuppressed(lrs, privateKey, ring, signerIndex, message) {
  return suppress(() => lrs.sign(privateKey, ring, signerIndex, message));
}

function verifySuppressed(lrs, signature, ring, message) {
  return suppress(() => lrs.verify(signature, ring, message));
}

// ── Statistics helpers ──────────────────────────────────────────────
function mean(arr) {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr) {
  const m = mean(arr);
  return Math.sqrt(arr.reduce((sum, v) => sum + (v - m) ** 2, 0) / arr.length);
}

function percentile(arr, p) {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil(p / 100 * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

module.exports = {
  ec, BN, crypto, fs, path,
  nowMs, suppress, suppressAsync,
  printHeader, printSubHeader, printResult, printTable,
  saveResults, generateRing, signSuppressed, verifySuppressed,
  mean, stddev, percentile
};
