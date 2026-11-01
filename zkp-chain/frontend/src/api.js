const API_ORIGIN = 'http://localhost:3000';
const API_BASE = `${API_ORIGIN}/api/v1`;

// Biometric feature extractor (model/app.py). The browser calls it directly so
// templates never pass through the API gateway; in deployment it runs on the
// voter's device or a supervised kiosk.
const BIOMETRIC_BASE = 'http://localhost:8000';

async function jsonOrThrow(res, fallback) {
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (e) { /* not JSON */ }
  if (!res.ok || (data && data.ok === false)) {
    throw new Error((data && (data.error || data.detail)) || text || fallback);
  }
  return data;
}

/**
 * Extract a biometric reading from an image via the local feature extractor.
 * @returns face: number[64] | iris: { irisCode, noiseMask }
 */
export const extractBiometric = async (mode, file) => {
  const form = new FormData();
  form.append('file', file);
  const url = mode === 'face' ? '/face/get-embedding' : '/iris/get-iriscode';
  const data = await jsonOrThrow(await fetch(BIOMETRIC_BASE + url, { method: 'POST', body: form }), 'Biometric extraction failed');
  return mode === 'face' ? data.embedding : { irisCode: data.iris_code, noiseMask: data.noise_mask };
};

// Capture-device attestor (api-server/sensor/attestor.js) — signs the live sample
const SENSOR_BASE = 'http://localhost:8001';

/**
 * Live capture through the authorised device. Sends the image and the public
 * electionId plus sessionCommit (a hiding commitment — never the nullifier).
 * @returns { template, sensorPublicKey, signature }
 */
export const attestCapture = async (mode, file, electionId, sessionCommit) => {
  const form = new FormData();
  form.append('file', file);
  form.append('mode', mode);
  form.append('electionId', electionId);
  form.append('sessionCommit', sessionCommit);
  return jsonOrThrow(await fetch(`${SENSOR_BASE}/attest`, { method: 'POST', body: form }), 'Capture attestation failed');
};

/** Public registry of authorised capture devices [{ax, ay}]. */
export const getSensors = async () => {
  const res = await fetch(`${API_BASE}/sensors`);
  return (await jsonOrThrow(res, 'Could not fetch sensor registry')).sensors;
};

/** RA enrolment: only the NID and the client-built commitment leave the device. */
export const registerCommitment = async (nidNumber, biometricMode, commitment) => {
  const res = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nidNumber, biometricMode, commitment })
  });
  return jsonOrThrow(res, 'Registration failed');
};

/** Public voter roll for a modality (Merkle leaves). */
export const getCommitments = async (mode) => {
  const res = await fetch(`${API_BASE}/commitments${mode === 'iris' ? '/iris' : ''}`);
  return (await jsonOrThrow(res, 'Could not fetch voter roll')).commitments;
};

/** On-chain ballot record { ballotId, numOptions, publicKey, electionId }. */
export const getChainBallot = async (ballotId) => {
  const res = await fetch(`${API_BASE}/ballot/${encodeURIComponent(ballotId)}/chain`);
  return (await jsonOrThrow(res, 'Ballot has no on-chain key yet')).ballot;
};

/** Circuit artifacts for in-browser proving. */
export const circuitArtifacts = (mode) => ({
  wasm: `${API_ORIGIN}/circuits/${mode}_auth.wasm`,
  zkey: `${API_ORIGIN}/circuits/${mode}_auth.zkey`,
});

/** Relay a client-built vote (proof, nullifier, ciphertexts) to the ledger. */
export const submitVote = async (tx) => {
  const res = await fetch(`${API_BASE}/vote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(tx)
  });
  return jsonOrThrow(res, 'Vote submission failed');
};

/**
 * Create a new election ballot
 */
export const createBallot = async (data) => {
  const res = await fetch(`${API_BASE}/ballot/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
};

/**
 * Get active election ballot
 */
export const getActiveBallot = async () => {
  const res = await fetch(`${API_BASE}/ballot/active`);
  if (!res.ok) return { ok: false, ballot: null };
  return res.json();
};

/**
 * Get ballot history list
 */
export const getBallotHistory = async () => {
  const res = await fetch(`${API_BASE}/ballot/history`);
  if (!res.ok) return { ok: false, ballots: [] };
  return res.json();
};

/**
 * Setup homomorphic encryption key for a ballot
 */
export const setupTally = async (ballotId) => {
  const res = await fetch(`${API_BASE}/tally/setup/${ballotId}`, {
    method: 'POST'
  });
  return res.json();
};

/**
 * Compute and decrypt homomorphic vote tallies
 */
export const computeTally = async (ballotId) => {
  const res = await fetch(`${API_BASE}/tally/compute/${ballotId}`, {
    method: 'POST'
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try { msg = JSON.parse(text).error || text; } catch (e) {}
    throw new Error(msg || 'Compute tally failed');
  }
  return res.json();
};

/**
 * Query system health and voter count statistics
 */
export const getSystemHealth = async () => {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    return null;
  }
};
