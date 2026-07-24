import React, { useState, useRef } from 'react';
import { registerUser } from './api';

export default function Register() {
  const [nidNumber, setNidNumber] = useState('');
  const [password, setPassword] = useState('');
  const [faceImg, setFaceImg] = useState(null);
  const [facePreview, setFacePreview] = useState(null);
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
    setFacePreview(null);
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
        setStatus({ loading: false, error: null, success: '✅ Registration successful! Your QR Code has been downloaded.' });
        resetForm();
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Registration failed.', success: null });
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-icon">🪪</div>
        <div>
          <h2>Voter Registration</h2>
          <p style={{ marginBottom: 0 }}>Create your secure digital voter identity</p>
        </div>
      </div>

      {status.error && <div className="alert alert-error">⚠️ {status.error}</div>}
      {status.success && <div className="alert alert-success">{status.success}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>NID Number</label>
          <input
            type="text"
            placeholder="Enter your National ID Number"
            value={nidNumber}
            onChange={e => setNidNumber(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input
            type="password"
            placeholder="Choose a secure password"
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

        <button type="submit" disabled={status.loading} className="btn-full">
          {status.loading ? <><span className="spinner" /> Registering...</> : '🔐 Register Voter'}
        </button>
      </form>
    </div>
  );
}
