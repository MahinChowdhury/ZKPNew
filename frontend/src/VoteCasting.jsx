import React, { useState, useRef } from 'react';
import { castVote } from './api';

export default function VoteCasting() {
  const [qrCode, setQrCode] = useState(null);
  const [password, setPassword] = useState('');
  const [faceImg, setFaceImg] = useState(null);
  const [voteChoice, setVoteChoice] = useState('');
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  const qrCodeRef = useRef(null);
  const faceImgRef = useRef(null);

  const resetForm = () => {
    setQrCode(null);
    setPassword('');
    setFaceImg(null);
    setVoteChoice('');
    if (qrCodeRef.current) {
      qrCodeRef.current.value = '';
    }
    if (faceImgRef.current) {
      faceImgRef.current.value = '';
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!qrCode || !faceImg) {
      setStatus({ ...status, error: 'Both QR Code and Face image are required.' });
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
         setStatus({ loading: false, error: null, success: 'Vote cast successfully!' });
         resetForm();
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Voting failed.', success: null });
    }
  };

  return (
    <div className="card">
      <h2 style={{ marginBottom: '1.5rem' }}>Cast your Vote</h2>
      {status.error && (
        <div style={{ color: 'var(--danger-color)', marginBottom: '1rem', padding: '0.75rem', backgroundColor: '#fef2f2', borderRadius: 'var(--radius-md)' }}>
          {status.error}
        </div>
      )}
      {status.success && (
        <div style={{ color: 'var(--success-color)', marginBottom: '1rem', padding: '0.75rem', backgroundColor: '#ecfdf5', borderRadius: 'var(--radius-md)' }}>
          {status.success}
        </div>
      )}

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
            placeholder="Your password" 
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
            onChange={e => setFaceImg(e.target.files[0])} 
            ref={faceImgRef}
            required 
          />
        </div>
        <div className="form-group">
          <label>Vote Choice</label>
          <input 
            type="text" 
            placeholder="Enter candidate name or ID" 
            value={voteChoice} 
            onChange={e => setVoteChoice(e.target.value)} 
            required 
          />
        </div>

        <button type="submit" disabled={status.loading} style={{ width: '100%', marginTop: '1rem' }}>
          {status.loading ? 'Casting Vote...' : 'Submit Vote'}
        </button>
      </form>
    </div>
  );
}
