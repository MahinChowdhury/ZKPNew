import React, { useState, useEffect, useRef } from 'react';
import { getActiveBallot, attestCapture, getSensors, getCommitments, getChainBallot, circuitArtifacts, submitVote } from './api';
import { openCredential, startVoteSession, prepareVote } from './crypto/voterClient';

export default function VoteCasting({ onVoteSuccess }) {
  const [biometricMode, setBiometricMode] = useState('face');
  const [activeBallot, setActiveBallot] = useState(null);
  const [ballotId, setBallotId] = useState('');
  const [qrCode, setQrCode] = useState(null);
  const [password, setPassword] = useState('');
  const [bioFile, setBioFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [voteChoice, setVoteChoice] = useState('');
  const [status, setStatus] = useState({ loading: false, error: null, success: null, receipt: null });

  const qrCodeRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    fetchBallot();
  }, []);

  const fetchBallot = async () => {
    try {
      const res = await getActiveBallot();
      if (res && res.ok && res.ballot) {
        setActiveBallot(res.ballot);
        setBallotId(res.ballot.id);
      }
    } catch (err) {
      console.warn("Could not fetch active ballot:", err);
    }
  };

  const handleModeSwitch = (mode) => {
    setBiometricMode(mode);
    setBioFile(null);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setStatus({ loading: false, error: null, success: null, receipt: null });
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setBioFile(file);
      setPreviewUrl(URL.createObjectURL(file));
    }
  };

  const resetForm = () => {
    setQrCode(null);
    setPassword('');
    setBioFile(null);
    setPreviewUrl(null);
    setVoteChoice('');
    if (qrCodeRef.current) qrCodeRef.current.value = '';
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!qrCode || !bioFile) {
      setStatus({
        ...status,
        error: `Please select both your credential file and live ${biometricMode === 'face' ? 'face photo' : 'iris scan'}.`
      });
      return;
    }
    if (!activeBallot) {
      setStatus({ ...status, error: 'No active ballot.' });
      return;
    }
    const choiceIndex = activeBallot.options.findIndex(o => o.name === voteChoice);
    if (choiceIndex < 0) {
      setStatus({ ...status, error: 'Please select a candidate option.' });
      return;
    }

    setStatus({ loading: true, error: null, success: null, receipt: null });

    try {
      // Everything below runs on this device; only the finished transaction is sent
      const credential = await openCredential(await qrCode.text(), password);
      if (credential.mode !== biometricMode) {
        throw new Error(`This credential was enrolled with ${credential.mode.toUpperCase()} — switch the mode above.`);
      }
      const [ballot, commitments, sensors] = await Promise.all([
        getChainBallot(activeBallot.id),
        getCommitments(biometricMode),
        getSensors(),
      ]);
      // The capture device signs the live sample for this vote session only
      const session = await startVoteSession(credential, ballot);
      const attestation = await attestCapture(biometricMode, bioFile, session.electionId, session.sessionCommit);
      const tx = await prepareVote({
        credential,
        session,
        attestation,
        sensors,
        ballot,
        choiceIndex,
        commitments,
        artifacts: circuitArtifacts(biometricMode),
      });

      const res = await submitVote(tx);
      setStatus({
        loading: false,
        error: null,
        success: 'Vote successfully cast and verified on-chain via ZK-SNARK.',
        receipt: res
      });
      resetForm();
      if (onVoteSuccess) onVoteSuccess();
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Voting failed.', success: null, receipt: null });
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2>Cast Your Vote</h2>
        <p>Authenticate with your biometric credential and cast an encrypted vote</p>
      </div>

      {/* Biometric Selector */}
      <div className="biometric-selector">
        <span className="selector-label">Biometric Verification Mode</span>
        <div className="mode-grid">
          <div
            className={`mode-card ${biometricMode === 'face' ? 'selected' : ''}`}
            onClick={() => handleModeSwitch('face')}
          >
            <div className="mode-title">Facial Proving</div>
            <div className="mode-desc">Squared Cosine Match</div>
          </div>
          <div
            className={`mode-card ${biometricMode === 'iris' ? 'selected' : ''}`}
            onClick={() => handleModeSwitch('iris')}
          >
            <div className="mode-title">Iris Proving</div>
            <div className="mode-desc">256-bit Hamming Distance</div>
          </div>
        </div>
      </div>

      {status.error && <div className="alert alert-error">{status.error}</div>}
      {status.success && (
        <div className="alert alert-success">
          <div>{status.success}</div>
          {status.receipt && (
            <div className="receipt-box">
              <div><strong>Tx ID:</strong> <code>{status.receipt.voteId}</code></div>
              <div><strong>On-Chain Status:</strong> Verified (Groth16 ZK-SNARK)</div>
              <div><strong>Nullifier:</strong> <code>{status.receipt.nullifier ? `${status.receipt.nullifier.slice(0, 20)}...` : 'Verified'}</code></div>
            </div>
          )}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Active Election Banner */}
        {activeBallot ? (
          <div className="election-banner">
            <div className="banner-tag">Active Election</div>
            <h3>{activeBallot.title}</h3>
            {activeBallot.description && <p>{activeBallot.description}</p>}
          </div>
        ) : (
          <div className="form-group">
            <label>Ballot ID</label>
            <input
              type="text"
              placeholder="Enter ballot ID"
              value={ballotId}
              onChange={e => setBallotId(e.target.value)}
              required
            />
          </div>
        )}

        {/* Candidate Selector */}
        {activeBallot && activeBallot.options && (
          <div className="form-group">
            <label>Select Candidate</label>
            <div className="candidate-grid">
              {activeBallot.options.map((opt, idx) => (
                <div
                  key={opt.id || idx}
                  className={`candidate-item ${voteChoice === opt.name ? 'selected' : ''}`}
                  onClick={() => setVoteChoice(opt.name)}
                >
                  <span>{opt.name}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {!activeBallot && (
          <div className="form-group">
            <label>Candidate Name</label>
            <input
              type="text"
              placeholder="Enter candidate name"
              value={voteChoice}
              onChange={e => setVoteChoice(e.target.value)}
              required
            />
          </div>
        )}

        <div className="form-group">
          <label>Encrypted Credential File</label>
          <input
            type="file"
            accept=".json,application/json"
            onChange={e => setQrCode(e.target.files[0])}
            ref={qrCodeRef}
            required
          />
        </div>

        <div className="form-group">
          <label>Credential Password</label>
          <input
            type="password"
            placeholder="Enter your password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label>{biometricMode === 'face' ? 'Live Face Verification Photo' : 'Live Iris Verification Scan'}</label>
          <input
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            ref={fileInputRef}
            required
          />
          {previewUrl && (
            <div className="preview-container">
              <img src={previewUrl} alt="Preview" className="preview-img" />
            </div>
          )}
        </div>

        <button type="submit" disabled={status.loading} className="btn-primary btn-full">
          {status.loading ? (
            <><span className="spinner" /> Generating ZK Proof...</>
          ) : (
            `Submit Encrypted Vote (${biometricMode === 'face' ? 'Face' : 'Iris'})`
          )}
        </button>
      </form>
    </div>
  );
}
