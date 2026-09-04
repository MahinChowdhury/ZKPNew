const API_BASE = 'http://localhost:3000/api/v1';

/**
 * Register user (Face or Iris mode)
 * @param {FormData} formData - contains nidNumber, password, biometricMode ('face' | 'iris'), and faceImg or irisImg
 */
export const registerUser = async (formData) => {
  const res = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    body: formData
  });

  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try { msg = JSON.parse(text).error || text; } catch (e) {}
    throw new Error(msg || 'Registration failed');
  }

  const blob = await res.blob();
  return { ok: true, qrCodeUrl: URL.createObjectURL(blob) };
};

/**
 * Cast vote using ZK-SNARK proof (Face or Iris mode)
 * @param {FormData} formData - contains ballotId, password, qrCode, biometricMode, faceImg/irisImg, voteChoice
 */
export const castVote = async (formData) => {
  const res = await fetch(`${API_BASE}/vote`, {
    method: 'POST',
    body: formData
  });

  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try { msg = JSON.parse(text).error || text; } catch (e) {}
    throw new Error(msg || 'Vote submission failed');
  }

  return res.json();
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
