import React, { useState, useRef } from 'react';
import { registerUser } from './api';

export default function Register() {
  const [nidNumber, setNidNumber] = useState('');
  const [password, setPassword] = useState('');
  const [faceImg, setFaceImg] = useState(null);
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  const faceImgRef = useRef(null);

  const downloadQRCode = (qrCodeUrl) => {
    const link = document.createElement('a');
    link.href = qrCodeUrl;
    link.download = 'my-voter-qrcode.png';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const resetForm = () => {
    setNidNumber('');
    setPassword('');
    setFaceImg(null);
    if (faceImgRef.current) {
      faceImgRef.current.value = '';
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!faceImg) {
      setStatus({ ...status, error: 'Face image is required.' });
      return;
    }

    setStatus({ loading: true, error: null, success: null });
    try {
      const formData = new FormData();
      formData.append('nidNumber', nidNumber);
      formData.append('password', password);
      formData.append('faceImg', faceImg);

      const res = await registerUser(formData);
      if (res.error) {
         setStatus({ loading: false, error: res.error, success: null });
      } else {
         downloadQRCode(res.qrCodeUrl);
         setStatus({ loading: false, error: null, success: 'Registration successful!' });
         resetForm();
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Registration failed.', success: null });
    }
  };

  return (
    <div className="card">
      <h2 style={{ marginBottom: '1.5rem' }}>User Registration</h2>
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
          <label>NID Number</label>
          <input 
            type="text" 
            placeholder="Enter your NID" 
            value={nidNumber} 
            onChange={e => setNidNumber(e.target.value)} 
            required 
          />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input 
            type="password" 
            placeholder="Choose a password" 
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

        <button type="submit" disabled={status.loading} style={{ width: '100%' }}>
          {status.loading ? 'Registering...' : 'Register'}
        </button>
      </form>
    </div>
  );
}
