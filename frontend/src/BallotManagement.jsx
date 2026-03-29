import React, { useState } from 'react';
import { createBallot, setupTally } from './api';

export default function BallotManagement() {
  const [title, setTitle] = useState('');
  const [options, setOptions] = useState(['Alice', 'Bob']);
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  const [setupBallotId, setSetupBallotId] = useState('');
  const [setupStatus, setSetupStatus] = useState({ loading: false, error: null, success: null });

  const handleSetup = async (e) => {
    e.preventDefault();
    if (!setupBallotId.trim()) {
      setSetupStatus({ loading: false, error: 'Ballot ID is required.', success: null });
      return;
    }
    setSetupStatus({ loading: true, error: null, success: null });
    try {
      const res = await setupTally(setupBallotId);
      if (res.error || res.ok === false) {
         setSetupStatus({ loading: false, error: res.error || 'Setup failed.', success: null });
      } else {
         setSetupStatus({ loading: false, error: null, success: 'Tally setup successful!' });
         setSetupBallotId('');
      }
    } catch (err) {
      setSetupStatus({ loading: false, error: err.message || 'Setup failed.', success: null });
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!title.trim() || options.length < 2) {
       setStatus({ loading: false, error: 'Title and at least two options are required.', success: null });
       return;
    }

    setStatus({ loading: true, error: null, success: null });
    try {
      const res = await createBallot({ title, options });
      if (res.error || res.ok === false) {
         setStatus({ loading: false, error: res.error || 'Failed to create ballot', success: null });
      } else {
         const ballotId = res.ballot?.id || res.id || res.ballotId;
         if (ballotId) {
             const setupRes = await setupTally(ballotId);
             if (setupRes.error || setupRes.ok === false) {
                 setStatus({ loading: false, error: `Ballot created, but homomorphic setup failed: ${setupRes.error || 'Unknown error'}`, success: null });
             } else {
                 setStatus({ loading: false, error: null, success: `Ballot created & homomorphic setup successful! Ballot ID: ${ballotId}` });
                 setTitle('');
                 setOptions(['', '']);
             }
         } else {
             setStatus({ loading: false, error: null, success: `Ballot created successfully, but no ballot ID returned.` });
             setTitle('');
             setOptions(['', '']);
         }
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Creation failed.', success: null });
    }
  };

  const handleOptionChange = (index, value) => {
    const newOptions = [...options];
    newOptions[index] = value;
    setOptions(newOptions);
  };

  const addOption = () => {
    setOptions([...options, '']);
  };

  const removeOption = (index) => {
    if (options.length > 2) {
      const newOptions = options.filter((_, i) => i !== index);
      setOptions(newOptions);
    }
  };

  return (
    <div className="card">
      <h2 style={{ marginBottom: '1.5rem' }}>Create Ballot</h2>
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

      <form onSubmit={handleCreate}>
        <div className="form-group">
          <label>Ballot Title</label>
          <input 
            type="text" 
            placeholder="e.g. Election 2025" 
            value={title} 
            onChange={e => setTitle(e.target.value)} 
            required 
          />
        </div>

        <div className="form-group">
          <label>Candidates / Options</label>
          {options.map((opt, index) => (
            <div key={index} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <input 
                type="text" 
                placeholder={`Option ${index + 1}`} 
                value={opt} 
                onChange={e => handleOptionChange(index, e.target.value)} 
                required 
                style={{ marginBottom: 0 }}
              />
              {options.length > 2 && (
                <button type="button" onClick={() => removeOption(index)} style={{ backgroundColor: 'var(--danger-color)' }}>
                  Remove
                </button>
              )}
            </div>
          ))}
          <button type="button" onClick={addOption} style={{ marginTop: '0.5rem', backgroundColor: 'var(--text-light)' }}>
            + Add Option
          </button>
        </div>

        <button type="submit" disabled={status.loading} style={{ width: '100%', marginTop: '1rem' }}>
          {status.loading ? 'Creating...' : 'Create Ballot'}
        </button>
      </form>

      <hr style={{ margin: '2rem 0', borderColor: 'var(--border-color)', borderBottom: 'none' }} />

      <h3 style={{ marginBottom: '1rem' }}>Setup Existing Ballot Tally</h3>
      {setupStatus.error && (
        <div style={{ color: 'var(--danger-color)', marginBottom: '1rem', padding: '0.75rem', backgroundColor: '#fef2f2', borderRadius: 'var(--radius-md)' }}>
          {setupStatus.error}
        </div>
      )}
      {setupStatus.success && (
        <div style={{ color: 'var(--success-color)', marginBottom: '1rem', padding: '0.75rem', backgroundColor: '#ecfdf5', borderRadius: 'var(--radius-md)' }}>
          {setupStatus.success}
        </div>
      )}

      <form onSubmit={handleSetup}>
        <div className="form-group" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <input 
            type="text" 
            placeholder="e.g. ballot_1774786248124" 
            value={setupBallotId} 
            onChange={e => setSetupBallotId(e.target.value)} 
            style={{ flex: 1, marginBottom: 0 }}
          />
          <button type="submit" disabled={setupStatus.loading} style={{ width: 'auto', whiteSpace: 'nowrap' }}>
            {setupStatus.loading ? 'Processing...' : 'Setup Tally'}
          </button>
        </div>
      </form>
    </div>
  );
}
