import React, { useState, useEffect } from 'react';
import { createBallot, setupTally, getActiveBallot } from './api';

export default function BallotManagement({ onBallotUpdated }) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [options, setOptions] = useState(['', '']);
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  
  const [activeBallot, setActiveBallot] = useState(null);
  const [setupBallotId, setSetupBallotId] = useState('');
  const [setupStatus, setSetupStatus] = useState({ loading: false, error: null, success: null });

  useEffect(() => {
    fetchActive();
  }, []);

  const fetchActive = async () => {
    try {
      const res = await getActiveBallot();
      if (res && res.ok && res.ballot) {
        setActiveBallot(res.ballot);
        setSetupBallotId(res.ballot.id);
      }
    } catch (e) {
      console.warn("Error fetching active ballot:", e);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    const filledOptions = options.filter(o => o.trim());
    if (!title.trim() || filledOptions.length < 2) {
      setStatus({ loading: false, error: 'A title and at least two candidate options are required.', success: null });
      return;
    }
    setStatus({ loading: true, error: null, success: null });
    try {
      const res = await createBallot({ title, description, options: filledOptions });
      if (res.error || res.ok === false) {
        setStatus({ loading: false, error: res.error || 'Failed to create ballot', success: null });
      } else {
        const ballotId = res.ballot?.id || res.id || res.ballotId;
        if (ballotId) {
          const setupRes = await setupTally(ballotId);
          if (setupRes.error || setupRes.ok === false) {
            setStatus({
              loading: false,
              error: `Ballot created, but homomorphic setup failed: ${setupRes.error || 'Unknown error'}`,
              success: null
            });
          } else {
            setStatus({
              loading: false,
              error: null,
              success: `Election ballot created and encryption key initialized. Ballot ID: ${ballotId}`
            });
            setTitle('');
            setDescription('');
            setOptions(['', '']);
            fetchActive();
            if (onBallotUpdated) onBallotUpdated();
          }
        }
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Creation failed.', success: null });
    }
  };

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
        setSetupStatus({ loading: false, error: null, success: 'Homomorphic setup successful!' });
        fetchActive();
      }
    } catch (err) {
      setSetupStatus({ loading: false, error: err.message || 'Setup failed.', success: null });
    }
  };

  const handleOptionChange = (index, value) => {
    const newOptions = [...options];
    newOptions[index] = value;
    setOptions(newOptions);
  };

  const addOption = () => setOptions([...options, '']);

  const removeOption = (index) => {
    if (options.length > 2) {
      setOptions(options.filter((_, i) => i !== index));
    }
  };

  return (
    <div>
      {/* Active Election Summary */}
      {activeBallot && (
        <div className="card">
          <div className="card-header">
            <h2>Current Active Election</h2>
            <p>Ballot ID: <code>{activeBallot.id}</code></p>
          </div>
          <div>
            <h3>{activeBallot.title}</h3>
            {activeBallot.description && <p>{activeBallot.description}</p>}
            <div className="pill-group">
              {activeBallot.options?.map((opt, idx) => (
                <span key={idx} className="pill-item">
                  {opt.name}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Create New Election */}
      <div className="card">
        <div className="card-header">
          <h2>Create New Election Ballot</h2>
          <p>Define candidate options and initialize ElGamal encryption keys</p>
        </div>

        {status.error && <div className="alert alert-error">{status.error}</div>}
        {status.success && <div className="alert alert-success">{status.success}</div>}

        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label>Election Title</label>
            <input
              type="text"
              placeholder="e.g. Presidential Election 2026"
              value={title}
              onChange={e => setTitle(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label>Description (Optional)</label>
            <input
              type="text"
              placeholder="Brief description of the election"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label>Candidates / Options</label>
            {options.map((opt, index) => (
              <div key={index} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <input
                  type="text"
                  placeholder={`Candidate ${index + 1}`}
                  value={opt}
                  onChange={e => handleOptionChange(index, e.target.value)}
                  required
                  style={{ marginBottom: 0 }}
                />
                {options.length > 2 && (
                  <button type="button" onClick={() => removeOption(index)} className="btn-danger btn-sm">
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button type="button" onClick={addOption} className="btn-secondary btn-sm" style={{ marginTop: '0.5rem' }}>
              + Add Candidate
            </button>
          </div>

          <button type="submit" disabled={status.loading} className="btn-primary btn-full" style={{ marginTop: '1rem' }}>
            {status.loading ? <><span className="spinner" /> Creating Ballot...</> : 'Create & Launch Election'}
          </button>
        </form>
      </div>

      {/* Manual Tally Setup */}
      <div className="card">
        <div className="card-header">
          <h2>Homomorphic Key Setup</h2>
          <p>Initialize encryption keys for an existing ballot ID</p>
        </div>

        {setupStatus.error && <div className="alert alert-error">{setupStatus.error}</div>}
        {setupStatus.success && <div className="alert alert-success">{setupStatus.success}</div>}

        <form onSubmit={handleSetup}>
          <div className="form-group" style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Enter Ballot ID"
              value={setupBallotId}
              onChange={e => setSetupBallotId(e.target.value)}
              style={{ flex: 1, marginBottom: 0 }}
            />
            <button type="submit" disabled={setupStatus.loading} className="btn-secondary" style={{ whiteSpace: 'nowrap' }}>
              {setupStatus.loading ? <><span className="spinner" /> Processing...</> : 'Setup Keys'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
