// ============================================================
// voterClient.js — everything secret happens here, on the voter's device
//
// The API gateway never sees the voter's secret key, salt, biometric
// template, or vote choice. It receives only:
//   registration:  (NID, commitment)                       — RA enrolment
//   voting:        (proof, publicSignals, nullifier, ciphertexts, ballotId)
//
// Pure ES module with no I/O: callers pass in biometric templates, public
// ledger data and circuit artifact locations (URLs in the browser, file
// paths in Node), so the same code runs in the frontend and in the tests.
//
// Hash encodings MUST stay byte-identical to api-server/crypto/homomorphic.js
// and chaincode/identity/lib/ballotCrypto.js.
// ============================================================

import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import elliptic from "elliptic";
import BN from "bn.js";
import hashjs from "hash.js";

export const MERKLE_LEVELS = 20;
export const SENSOR_LEVELS = 10;     // authorised capture-device registry depth
export const FACE_SCALE = 500000;    // σ = 5e5, matches circuit range check |x| < 2^19
export const IRIS_CODE_SIZE = 256;
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PBKDF2_ITERATIONS = 600000;    // OWASP 2023 guidance for PBKDF2-SHA256

const ec = new elliptic.ec("secp256k1");
const subtle = globalThis.crypto.subtle;
const mod = (a) => ((a % P) + P) % P;

// ------------------------------------------------------------
// Primitives
// ------------------------------------------------------------
function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const sha256Hex = (str) => hashjs.sha256().update(Array.from(new TextEncoder().encode(str))).digest("hex");
const randomScalar = () => new BN(toHex(randomBytes(32)), 16).umod(ec.curve.n);

let _poseidon;
async function H(...xs) {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon.F.toObject(_poseidon(xs.map((x) => _poseidon.F.e(mod(BigInt(x))))));
}

// First 128 bits of SHA256(ballotId) — same derivation the chaincode checks
export function electionIdFor(ballotId) {
  return BigInt("0x" + sha256Hex(String(ballotId)).slice(0, 32));
}

// ------------------------------------------------------------
// Attested enrollment (enroll_auth.circom, FINDINGS C26)
// ------------------------------------------------------------
// Election slot of an enrollment attestation: no electionId (< 2^128) equals it
export const ENROLL_DOMAIN = 1n << 200n;

// NID binding of an enrollment: first 248 bits of SHA256(nidHash), as the chaincode derives it
export function nidFieldFor(nidHash) {
  return BigInt("0x" + sha256Hex(String(nidHash)).slice(0, 62));
}

// What the enrollment kiosk binds its signature to, in SensorAttestation's session slot
export async function enrollmentSessionCommit(nidHash) {
  return H(nidFieldFor(nidHash), 0n);
}

// ------------------------------------------------------------
// Biometric templates (circuit encoding)
// ------------------------------------------------------------
export function scaleEmbedding(floats) {
  return floats.map((v) => BigInt(Math.round(v * FACE_SCALE)));
}

// Mask-aware uniform striding to 256 bits (mirrors crypto/iris-snark.js)
export function downsampleIrisCode(fullCode, fullMask) {
  const valid = [];
  for (let i = 0; i < fullCode.length; i++) if (fullMask[i] === 1) valid.push(i);
  const out = new Array(IRIS_CODE_SIZE).fill(0);
  if (valid.length < IRIS_CODE_SIZE) {
    for (let i = 0; i < valid.length; i++) out[i] = fullCode[valid[i]] ? 1 : 0;
    return out;
  }
  const step = valid.length / IRIS_CODE_SIZE;
  for (let i = 0; i < IRIS_CODE_SIZE; i++) out[i] = fullCode[valid[Math.floor(i * step)]] ? 1 : 0;
  return out;
}

/**
 * Convert a raw reading from the biometric service into the circuit template.
 *   face: number[128] (L2-normalised)         → BigInt[128]
 *   iris: { irisCode: 0/1[], noiseMask: 0/1[] } → 0/1[256]
 */
export function toTemplate(mode, raw) {
  return mode === "face" ? scaleEmbedding(raw) : downsampleIrisCode(raw.irisCode, raw.noiseMask);
}

// PackedCoordHash(d, 19): offset coordinates x + 2^19 take 20-bit slots,
// floor(253 / 20) = 12 slots per field element, then one Poseidon per 16 elements.
const FACE_COORD_BITS = 19n;
const FACE_SLOTS = 12;

async function packedCoordHash(template) {
  const off = 1n << FACE_COORD_BITS;
  const packed = [];
  for (let e = 0; e * FACE_SLOTS < template.length; e++) {
    let v = 0n;
    for (let j = 0; j < FACE_SLOTS && e * FACE_SLOTS + j < template.length; j++) {
      const x = BigInt(template[e * FACE_SLOTS + j]);
      if (x < -off || x >= off) throw new Error(`Face coordinate ${x} outside the circuit range`);
      v += (x + off) << ((FACE_COORD_BITS + 1n) * BigInt(j));
    }
    packed.push(v);
  }
  if (packed.length <= 16) return H(...packed);
  const groups = [];
  for (let q = 0; q < packed.length; q += 16) groups.push(await H(...packed.slice(q, q + 16)));
  return H(...groups);
}

/**
 * Unsalted digest of a template, exactly as the circuit computes it
 * (PackedCoordHash for face, PackedBitsHash for iris). The capture
 * device signs this for the live sample.
 */
export async function templateDigest(mode, template) {
  if (mode === "face") return packedCoordHash(template);
  const packed = [];
  for (let i = 0; i < 32; i++) {
    let v = 0n;
    for (let j = 0; j < 8; j++) v += BigInt(template[i * 8 + j]) << BigInt(j);
    packed.push(v);
  }
  const chunks = [];
  for (let i = 0; i < 4; i++) chunks.push(await H(...packed.slice(i * 8, i * 8 + 8)));
  return H(...chunks);
}

const bioHash = async (mode, template, salt) => H(await templateDigest(mode, template), salt);

/** Message the capture device signs: Poseidon(liveDigest, electionId, sessionCommit). */
export async function attestationMessage(liveDigest, electionId, sessionCommit) {
  return H(liveDigest, electionId, sessionCommit);
}

// ------------------------------------------------------------
// Registration: keys and salt are generated here, never by the RA
// ------------------------------------------------------------
export async function createCredential(mode, template) {
  if (mode !== "face" && mode !== "iris") throw new Error(`Unknown biometric mode: ${mode}`);
  const salt = BigInt("0x" + toHex(randomBytes(16)));
  let sk = BigInt("0x" + toHex(randomBytes(32))) & ((1n << 252n) - 1n);
  if (sk === 0n) sk = 1n;
  const commitment = await H(await bioHash(mode, template, salt), sk);
  return {
    v: 1,
    mode,
    salt: salt.toString(),
    sk: sk.toString(),
    template: template.map(String),
    commitment: commitment.toString(),
  };
}

// Password-encrypted credential file (PBKDF2-SHA256 → AES-256-GCM)
async function credentialKey(password, salt, iterations) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function sealCredential(credential, password) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = await credentialKey(password, salt, PBKDF2_ITERATIONS);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(credential)));
  return JSON.stringify({
    format: "bbzkv-credential-v1", kdf: "PBKDF2-SHA256", iterations: PBKDF2_ITERATIONS,
    salt: b64(salt), iv: b64(iv), ciphertext: b64(ct),
  });
}

export async function openCredential(sealedJSON, password) {
  const s = JSON.parse(sealedJSON);
  if (s.format !== "bbzkv-credential-v1") throw new Error("Not a BBZKV credential file");
  const key = await credentialKey(password, unb64(s.salt), s.iterations);
  let pt;
  try {
    pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(s.iv) }, key, unb64(s.ciphertext));
  } catch {
    throw new Error("Wrong password or corrupted credential file");
  }
  return JSON.parse(new TextDecoder().decode(pt));
}

// ------------------------------------------------------------
// Merkle path over the public commitment list
// ------------------------------------------------------------
async function merklePath(leafList, leaf, levels, notFound) {
  const leaves = leafList.map((c) => BigInt(c));
  const index = leaves.findIndex((c) => c === leaf);
  if (index < 0) throw new Error(notFound);
  const z = [0n];
  for (let i = 0; i < levels; i++) z.push(await H(z[i], z[i]));
  let layer = new Map(leaves.map((v, i) => [i, v]));
  const pathElements = [], pathIndices = [];
  let idx = index;
  for (let lvl = 0; lvl < levels; lvl++) {
    pathElements.push(layer.get(idx ^ 1) ?? z[lvl]);
    pathIndices.push(idx & 1);
    const next = new Map();
    for (const p of new Set([...layer.keys()].map((i) => i >> 1))) {
      next.set(p, await H(layer.get(2 * p) ?? z[lvl], layer.get(2 * p + 1) ?? z[lvl]));
    }
    layer = next;
    idx >>= 1;
  }
  return { root: layer.get(0) ?? z[levels], pathElements, pathIndices };
}

// ------------------------------------------------------------
// Ballot encryption: exponential ElGamal + Σ-OR + sum-to-one
// ------------------------------------------------------------
const hex64 = (p) => [p.getX().toString(16, 64), p.getY().toString(16, 64)];
const xy = (p) => ({ x: p.getX().toString(16), y: p.getY().toString(16) });

function challenge(tag, points, context) {
  return new BN(sha256Hex([tag, ...points.flatMap(hex64), context].join("|")), 16).umod(ec.curve.n);
}

function proveBit(pk, c1, c2, m, r, context) {
  const n = ec.curve.n, G = ec.g;
  const w = randomScalar(), dFake = randomScalar(), rFake = randomScalar();
  let a1, b1, a2, b2, d1, d2, r1, r2;
  if (m === 0) {
    a1 = G.mul(w); b1 = pk.mul(w);
    d2 = dFake; r2 = rFake;
    a2 = G.mul(r2).add(c1.mul(d2));
    b2 = pk.mul(r2).add(c2.add(G.neg()).mul(d2));
    d1 = challenge("bbzkv-sigma-or-v1", [pk, c1, c2, a1, b1, a2, b2], context).sub(d2).umod(n);
    r1 = w.sub(d1.mul(r)).umod(n);
  } else {
    a2 = G.mul(w); b2 = pk.mul(w);
    d1 = dFake; r1 = rFake;
    a1 = G.mul(r1).add(c1.mul(d1));
    b1 = pk.mul(r1).add(c2.mul(d1));
    d2 = challenge("bbzkv-sigma-or-v1", [pk, c1, c2, a1, b1, a2, b2], context).sub(d1).umod(n);
    r2 = w.sub(d2.mul(r)).umod(n);
  }
  return {
    a1: xy(a1), b1: xy(b1), a2: xy(a2), b2: xy(b2),
    d1: d1.toString(16), d2: d2.toString(16), r1: r1.toString(16), r2: r2.toString(16),
  };
}

export function encryptBallot(pkXY, numOptions, choiceIndex, ballotId, nullifier) {
  if (!Number.isInteger(choiceIndex) || choiceIndex < 0 || choiceIndex >= numOptions) {
    throw new Error("Invalid choice");
  }
  const pk = ec.curve.point(new BN(pkXY.x, 16), new BN(pkXY.y, 16));
  if (!pk.validate()) throw new Error("Ballot public key is not on the curve");
  const ciphertexts = [];
  let C1 = null, C2 = null, R = new BN(0);
  for (let j = 0; j < numOptions; j++) {
    const m = j === choiceIndex ? 1 : 0;
    const r = randomScalar();
    const c1 = ec.g.mul(r);
    const c2 = (m ? ec.g : ec.curve.point(null, null)).add(pk.mul(r));
    ciphertexts.push({ c1: xy(c1), c2: xy(c2), validityProof: proveBit(pk, c1, c2, m, r, `${ballotId}|${nullifier}|opt${j}`) });
    C1 = C1 ? C1.add(c1) : c1;
    C2 = C2 ? C2.add(c2) : c2;
    R = R.add(r);
  }
  R = R.umod(ec.curve.n);
  const w = randomScalar();
  const A = ec.g.mul(w), B = pk.mul(w);
  const e = challenge("bbzkv-sum-one-v1", [pk, C1, C2, A, B], `${ballotId}|${nullifier}|sum`);
  const sumProof = { A: xy(A), B: xy(B), z: w.add(e.mul(R)).umod(ec.curve.n).toString(16) };
  return { ciphertexts, sumProof };
}

export function computeVoteBinding(ballotId, encryptedBallot) {
  const cts = encryptedBallot.ciphertexts.map((c) => [c.c1.x, c.c1.y, c.c2.x, c.c2.y].join(":")).join(",");
  return BigInt("0x" + sha256Hex(`bbzkv-vote-binding-v1|${ballotId}|${cts}`).slice(0, 62));
}

// ------------------------------------------------------------
// Vote
// ------------------------------------------------------------
/**
 * Start a vote session before the live capture. The capture device is
 * given only sessionCommit = Poseidon(nullifier, sessionNonce): a hiding
 * commitment, so the device that sees the voter cannot link them to the
 * ballot, while its signature is usable for this one vote only.
 */
export async function startVoteSession(credential, ballot) {
  const electionId = electionIdFor(ballot.ballotId);
  if (String(ballot.electionId) !== electionId.toString()) {
    throw new Error("Ballot record electionId does not match its ballotId — refusing to vote");
  }
  const nullifier = await H(BigInt(credential.sk), electionId);
  const sessionNonce = BigInt("0x" + toHex(randomBytes(31)));
  const sessionCommit = await H(nullifier, sessionNonce);
  return {
    electionId: electionId.toString(),
    nullifier: nullifier.toString(),
    sessionNonce: sessionNonce.toString(),
    sessionCommit: sessionCommit.toString(),
  };
}

/**
 * Prove that a face credential's commitment opens to the template a
 * registered enrollment kiosk captured for this NID (enroll_auth.circom).
 * The credential must have been created from attestation.template.
 * Returns { proof, publicSignals } for the RA's register transaction.
 */
export async function proveEnrollment({ credential, attestation, sensors, nidHash, artifacts }) {
  if (credential.mode !== "face") throw new Error("Attested enrollment is implemented for face only");
  if (attestation.template.some((x, i) => String(x) !== credential.template[i])) {
    throw new Error("Credential template differs from the attested enrollment capture");
  }
  const sensorLeaves = [];
  for (const s of sensors) sensorLeaves.push(await H(s.ax, s.ay));
  const sensorPath = await merklePath(
    sensorLeaves, await H(attestation.sensorPublicKey.ax, attestation.sensorPublicKey.ay), SENSOR_LEVELS,
    "The enrollment kiosk that signed this capture is not an authorised device");
  const input = {
    commitment: credential.commitment,
    nidField: nidFieldFor(nidHash).toString(),
    sensorRoot: sensorPath.root.toString(),
    enrolled: credential.template.map((x) => mod(BigInt(x)).toString()),
    salt: credential.salt,
    secretKey: credential.sk,
    sensorAx: String(attestation.sensorPublicKey.ax),
    sensorAy: String(attestation.sensorPublicKey.ay),
    sigR8x: String(attestation.signature.R8x),
    sigR8y: String(attestation.signature.R8y),
    sigS: String(attestation.signature.S),
    sensorPathElements: sensorPath.pathElements.map(String),
    sensorPathIndices: sensorPath.pathIndices.map(String),
  };
  try {
    return await snarkjs.groth16.fullProve(input, artifacts.wasm, artifacts.zkey);
  } catch (err) {
    throw new Error(`Enrollment capture attestation is invalid (proof could not be generated): ${err.message}`);
  }
}

/**
 * Build a complete, self-verifying vote transaction.
 *   credential   — from openCredential()
 *   session      — from startVoteSession() (same credential and ballot)
 *   attestation  — capture-device response { template, sensorPublicKey: {ax, ay}, signature: {R8x, R8y, S} }
 *   sensors      — public registry of authorised capture devices [{ax, ay}]
 *   ballot       — on-chain record { ballotId, numOptions, publicKey, electionId }
 *   choiceIndex  — index into the ballot's options (never leaves this function in clear)
 *   commitments  — public commitment list for credential.mode
 *   artifacts    — { wasm, zkey } URLs (browser) or file paths (Node)
 *   timings      — optional object filled with per-phase milliseconds (local only, never sent)
 */
export async function prepareVote({ credential, session, attestation, sensors, ballot, choiceIndex, commitments, artifacts, timings = {} }) {
  const tick = (() => { let t = performance.now(); return (k) => { const n = performance.now(); timings[k] = n - t; t = n; }; })();
  const electionId = electionIdFor(ballot.ballotId);
  if (session.electionId !== electionId.toString()) {
    throw new Error("Vote session was started for a different ballot");
  }
  const sk = BigInt(credential.sk);
  const salt = BigInt(credential.salt);
  const nullifier = session.nullifier;
  const { root, pathElements, pathIndices } = await merklePath(
    commitments, BigInt(credential.commitment), MERKLE_LEVELS,
    "Your commitment is not on the voter roll for this modality");

  const sensorLeaves = [];
  for (const s of sensors) sensorLeaves.push(await H(s.ax, s.ay));
  const sensorPath = await merklePath(
    sensorLeaves, await H(attestation.sensorPublicKey.ax, attestation.sensorPublicKey.ay), SENSOR_LEVELS,
    "The capture device that signed this sample is not an authorised sensor");
  const liveTemplate = attestation.template;
  tick("merklePaths");

  const encryptedBallot = encryptBallot(ballot.publicKey, ballot.numOptions, choiceIndex, ballot.ballotId, nullifier);
  const voteBinding = computeVoteBinding(ballot.ballotId, encryptedBallot);
  tick("encryptBallot");

  const common = {
    merkleRoot: root.toString(),
    nullifier,
    electionId: electionId.toString(),
    voteBinding: voteBinding.toString(),
    sensorRoot: sensorPath.root.toString(),
    salt: salt.toString(),
    secretKey: sk.toString(),
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
    sessionNonce: session.sessionNonce,
    sensorAx: String(attestation.sensorPublicKey.ax),
    sensorAy: String(attestation.sensorPublicKey.ay),
    sigR8x: String(attestation.signature.R8x),
    sigR8y: String(attestation.signature.R8y),
    sigS: String(attestation.signature.S),
    sensorPathElements: sensorPath.pathElements.map(String),
    sensorPathIndices: sensorPath.pathIndices.map(String),
  };
  const input = credential.mode === "face"
    ? { ...common, embedding: liveTemplate.map((x) => mod(BigInt(x)).toString()), registeredEmbedding: credential.template.map((x) => mod(BigInt(x)).toString()) }
    : { ...common, irisCodeLive: liveTemplate.map(String), irisCodeRegistered: credential.template.map(String) };

  let proof, publicSignals;
  try {
    // Witness and proof as separate steps so their costs can be reported
    const wtns = { type: "mem" };
    await snarkjs.wtns.calculate(input, artifacts.wasm, wtns);
    tick("witness");
    ({ proof, publicSignals } = await snarkjs.groth16.prove(artifacts.zkey, wtns));
    tick("prove");
  } catch (err) {
    // The circuit rejects (assert fails) when the live sample does not match
    // the template or the capture-device attestation is invalid
    throw new Error(`Biometric did not match the enrolled template or the capture attestation is invalid (proof could not be generated): ${err.message}`);
  }
  return { proof, publicSignals, nullifier, encryptedBallot, ballotId: ballot.ballotId, biometricMode: credential.mode };
}
