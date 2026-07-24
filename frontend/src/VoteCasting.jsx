import React, { useState, useRef } from 'react';
import { castVote } from './api';

export default function VoteCasting() {
  const [qrCode, setQrCode] = useState(null);
  const [password, setPassword] = useState('');
  const [faceImg, setFaceImg] = useState(null);
  const [facePreview, setFacePreview] = useState(null);
  const [voteChoice, setVoteChoice] = useState('');
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  const qrCodeRef = useRef(null);
  const faceImgRef = useRef(null);

  const resetForm = () => {
    setQrCode(null);
    setPassword('');
    setFaceImg(null);
    setFacePreview(null);
    setVoteChoice('');
    if (qrCodeRef.current) qrCodeRef.current.value = '';
    if (faceImgRef.current) faceImgRef.current.value = '';
  };

  const handleFaceChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setFaceImg(file);
      setFacePreview(URL.createObjectURL(file));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!qrCode || !faceImg) {
      setStatus({ ...status, error: 'Both QR Code image and Face image are required.' });
      return;
    }
    setStatus({ loading: true, error: null, success: null });
    try {
      const formData = new FormData();
      formData.append('qrCode', qrCode);
      formData.append('password', password);
      formData.append('faceImg', faceImg);
      formData.append('voteChoice', voteChoice);

      const res = await castVote(formData);
      if (res.error) {
        setStatus({ loading: false, error: res.error, success: null });
      } else {
        setStatus({ loading: false, error: null, success: '✅ Your vote has been cast and cryptographically sealed on the blockchain.' });
        resetForm();
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Voting failed.', success: null });
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-icon">🗳️</div>
        <div>
          <h2>Cast Your Vote</h2>
          <p style={{ marginBottom: 0 }}>Authenticate with biometrics and submit your encrypted vote</p>
        </div>
      </div>

      {status.error && <div className="alert alert-error">⚠️ {status.error}</div>}
      {status.success && <div className="alert alert-success">{status.success}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>QR Code Image</label>
          <input
            type="file"
            accept="image/*"
            onChange={e => setQrCode(e.target.files[0])}
            ref={qrCodeRef}
            required
          />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input
            type="password"
            placeholder="Your registered password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label>Face Image</label>
          <input
            type="file"
            accept="image/*"
            onChange={handleFaceChange}
            ref={faceImgRef}
            required
          />
          {facePreview && (
            <div className="image-preview">
              <img src={facePreview} alt="Face preview" />
            </div>
          )}
        </div>
        <div className="form-group">
          <label>Vote Choice</label>
          <input
            type="text"
            placeholder="Enter candidate name or index"
            value={voteChoice}
            onChange={e => setVoteChoice(e.target.value)}
            required
          />
        </div>

        <button type="submit" disabled={status.loading} className="btn-full" style={{ marginTop: '1rem' }}>
          {status.loading ? <><span className="spinner" /> Generating ZK Proof...</> : '🔒 Submit Encrypted Vote'}
        </button>
      </form>
    </div>
  );
}
