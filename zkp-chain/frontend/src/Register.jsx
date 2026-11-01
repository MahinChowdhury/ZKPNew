import React, { useState, useRef } from 'react';
import { extractBiometric, registerCommitment } from './api';
import { createCredential, sealCredential, toTemplate } from './crypto/voterClient';

export default function Register({ onRegistrationSuccess }) {
  const [biometricMode, setBiometricMode] = useState('face');
  const [nidNumber, setNidNumber] = useState('');
  const [password, setPassword] = useState('');
  const [bioFile, setBioFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  const fileInputRef = useRef(null);

  const handleModeSwitch = (mode) => {
    setBiometricMode(mode);
    setBioFile(null);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setStatus({ loading: false, error: null, success: null });
  };

  const downloadCredential = (sealedJSON, mode) => {
    const url = URL.createObjectURL(new Blob([sealedJSON], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `voter-credential-${mode}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const resetForm = () => {
    setNidNumber('');
    setPassword('');
    setBioFile(null);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setBioFile(file);
      setPreviewUrl(URL.createObjectURL(file));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!bioFile) {
      setStatus({ ...status, error: `Please upload a ${biometricMode === 'face' ? 'face photo' : 'iris scan'} image.` });
      return;
    }
    setStatus({ loading: true, error: null, success: null });
    try {
      // Template, salt and secret key are created here and never sent anywhere
      const reading = await extractBiometric(biometricMode, bioFile);
      const credential = await createCredential(biometricMode, toTemplate(biometricMode, reading));
      const sealed = await sealCredential(credential, password);

      // The RA receives only the NID (for deduplication) and the commitment
      await registerCommitment(nidNumber, biometricMode, credential.commitment);

      downloadCredential(sealed, biometricMode);
      setStatus({
        loading: false,
        error: null,
        success: `Registration successful (${biometricMode.toUpperCase()} mode). Your password-encrypted credential file has been downloaded — keep it; it cannot be re-issued.`
      });
      resetForm();
      if (onRegistrationSuccess) onRegistrationSuccess();
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Registration failed.', success: null });
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2>Voter Registration</h2>
        <p>Register your identity commitments on the blockchain ledger</p>
      </div>

      {status.error && <div className="alert alert-error">{status.error}</div>}
      {status.success && <div className="alert alert-success">{status.success}</div>}

      <form onSubmit={handleSubmit}>
        {/* Biometric Modality Selector */}
        <div className="biometric-selector">
          <span className="selector-label">Biometric Modality</span>
          <div className="mode-grid">
            <div
              className={`mode-card ${biometricMode === 'face' ? 'selected' : ''}`}
              onClick={() => handleModeSwitch('face')}
            >
              <div className="mode-title">Facial Recognition</div>
              <div className="mode-desc">ArcFace PCA-128 Cosine Similarity</div>
            </div>
            <div
              className={`mode-card ${biometricMode === 'iris' ? 'selected' : ''}`}
              onClick={() => handleModeSwitch('iris')}
            >
              <div className="mode-title">Iris Scanning</div>
              <div className="mode-desc">256-bit Hamming Distance</div>
            </div>
          </div>
        </div>

        <div className="form-group">
          <label>National ID Number</label>
          <input
            type="text"
            placeholder="Enter your NID number"
            value={nidNumber}
            onChange={e => setNidNumber(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label>Credential Password</label>
          <input
            type="password"
            placeholder="Create a password to encrypt your credential"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label>{biometricMode === 'face' ? 'Face Image' : 'Iris Image Scan'}</label>
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
            <><span className="spinner" /> Registering...</>
          ) : (
            `Register Voter (${biometricMode === 'face' ? 'Face' : 'Iris'})`
          )}
        </button>
      </form>
    </div>
  );
}
