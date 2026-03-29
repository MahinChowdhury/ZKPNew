const API_BASE = 'http://localhost:3000/api/v1';

export const registerUser = async (formData) => {
  const res = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    body: formData // contains nidNumber, password, faceImg
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

export const createBallot = async (data) => {
  const res = await fetch(`${API_BASE}/ballot/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data) // contains title, options
  });
  return res.json();
};

export const castVote = async (formData) => {
  const res = await fetch(`${API_BASE}/vote`, {
    method: 'POST',
    body: formData // contains qrCode, password, faceImg, voteChoice
  });
  return res.json();
};

export const setupTally = async (ballotId) => {
  // Assuming POST since it might be a state-changing operation setup.
  const res = await fetch(`${API_BASE}/tally/setup/${ballotId}`, {
    method: 'POST'
  });
  return res.json();
};

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
