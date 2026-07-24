import React, { useState } from 'react';
import { createBallot, setupTally } from './api';

export default function BallotManagement() {
  const [title, setTitle] = useState('');
  const [options, setOptions] = useState(['', '']);
  const [status, setStatus] = useState({ loading: false, error: null, success: null });
  const [setupBallotId, setSetupBallotId] = useState('');
  const [setupStatus, setSetupStatus] = useState({ loading: false, error: null, success: null });

  const handleCreate = async (e) => {
    e.preventDefault();
    const filledOptions = options.filter(o => o.trim());
    if (!title.trim() || filledOptions.length < 2) {
      setStatus({ loading: false, error: 'A title and at least two candidate options are required.', success: null });
      return;
    }
    setStatus({ loading: true, error: null, success: null });
    try {
      const res = await createBallot({ title, options: filledOptions });
      if (res.error || res.ok === false) {
        setStatus({ loading: false, error: res.error || 'Failed to create ballot', success: null });
      } else {
        const ballotId = res.ballot?.id || res.id || res.ballotId;
        if (ballotId) {
          const setupRes = await setupTally(ballotId);
          if (setupRes.error || setupRes.ok === false) {
            setStatus({ loading: false, error: `Ballot created, but homomorphic setup failed: ${setupRes.error || 'Unknown error'}`, success: null });
          } else {
            setStatus({ loading: false, error: null, success: `✅ Ballot created & homomorphic tally setup done! Ballot ID: ${ballotId}` });
            setTitle('');
            setOptions(['', '']);
          }
        } else {
          setStatus({ loading: false, error: null, success: `✅ Ballot created successfully.` });
          setTitle('');
          setOptions(['', '']);
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
        setSetupStatus({ loading: false, error: null, success: '✅ Tally setup successful!' });
        setSetupBallotId('');
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
    <>
      <div className="card">
        <div className="card-header">
          <div className="card-icon">🗳️</div>
          <div>
            <h2>Create Ballot</h2>
            <p style={{ marginBottom: 0 }}>Define candidates and launch a new election ballot</p>
          </div>
        </div>

        {status.error && <div className="alert alert-error">⚠️ {status.error}</div>}
        {status.success && <div className="alert alert-success">{status.success}</div>}

        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label>Ballot Title</label>
            <input
              type="text"
              placeholder="e.g. General Election 2025"
              value={title}
              onChange={e => setTitle(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label>Candidates / Options</label>
            {options.map((opt, index) => (
              <div key={index} className="option-row">
                <span className="option-number">{index + 1}</span>
                <input
                  type="text"
                  placeholder={`Candidate ${index + 1}`}
                  value={opt}
                  onChange={e => handleOptionChange(index, e.target.value)}
                  required
                  style={{ marginBottom: 0, flex: 1 }}
                />
                {options.length > 2 && (
                  <button type="button" onClick={() => removeOption(index)} className="btn-danger btn-sm">
                    ✕
                  </button>
                )}
              </div>
            ))}
            <button type="button" onClick={addOption} className="btn-secondary btn-sm" style={{ marginTop: '0.75rem' }}>
              + Add Candidate
            </button>
          </div>

          <button type="submit" disabled={status.loading} className="btn-full" style={{ marginTop: '1rem' }}>
            {status.loading ? <><span className="spinner" /> Creating...</> : '🚀 Create Ballot'}
          </button>
        </form>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-icon">⚙️</div>
          <div>
            <h3>Setup Existing Ballot Tally</h3>
            <p style={{ marginBottom: 0 }}>Initialize homomorphic encryption for an existing ballot</p>
          </div>
        </div>

        {setupStatus.error && <div className="alert alert-error">⚠️ {setupStatus.error}</div>}
        {setupStatus.success && <div className="alert alert-success">{setupStatus.success}</div>}

        <form onSubmit={handleSetup}>
          <div className="form-group" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="e.g. ballot_1774786248124"
              value={setupBallotId}
              onChange={e => setSetupBallotId(e.target.value)}
              style={{ flex: 1, marginBottom: 0 }}
            />
            <button type="submit" disabled={setupStatus.loading} style={{ whiteSpace: 'nowrap' }}>
              {setupStatus.loading ? <><span className="spinner" /> Processing...</> : '⚙️ Setup Tally'}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}
