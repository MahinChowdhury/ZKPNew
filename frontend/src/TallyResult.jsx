import React, { useState } from 'react';
import { computeTally } from './api';

export default function TallyResult() {
  const [ballotId, setBallotId] = useState('');
  const [status, setStatus] = useState({ loading: false, error: null, success: null, data: null });

  const handleCompute = async () => {
    if (!ballotId.trim()) {
      setStatus({ ...status, error: 'Ballot ID is required.' });
      return;
    }
    setStatus({ loading: true, error: null, success: null, data: null });
    try {
      const res = await computeTally(ballotId);
      if (res.error) {
        setStatus({ loading: false, error: res.error, success: null, data: null });
      } else {
        setStatus({ loading: false, error: null, success: '✅ Tally computed and decrypted successfully!', data: res });
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Compute failed.', success: null, data: null });
    }
  };

  const renderResults = (data) => {
    // Try to render results as a visual tally table
    const results = data.results || data.tally || data;
    if (typeof results === 'object' && !Array.isArray(results)) {
      const entries = Object.entries(results).filter(([k]) => k !== 'ballotId' && k !== 'ok');
      if (entries.length > 0) {
        const maxVotes = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
        return (
          <div className="tally-results">
            <h4>📊 Election Results</h4>
            {entries.map(([candidate, votes]) => {
              const pct = Math.round((Number(votes) / maxVotes) * 100);
              return (
                <div key={candidate} className="tally-row">
                  <div className="tally-label">
                    <span className="tally-candidate">{candidate}</span>
                    <span className="tally-votes">{votes} votes</span>
                  </div>
                  <div className="tally-bar-track">
                    <div className="tally-bar-fill" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        );
      }
    }
    // Fallback: raw JSON
    return (
      <div className="json-output">
        <h4>Raw Result Data:</h4>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </div>
    );
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-icon">📊</div>
        <div>
          <h2>Tally Results</h2>
          <p style={{ marginBottom: 0 }}>Decrypt and display homomorphic tally for a ballot</p>
        </div>
      </div>

      {status.error && <div className="alert alert-error">⚠️ {status.error}</div>}
      {status.success && <div className="alert alert-success">{status.success}</div>}

      {status.data && renderResults(status.data)}

      <div className="form-group">
        <label>Ballot ID</label>
        <input
          type="text"
          placeholder="e.g. ballot_1774786248124"
          value={ballotId}
          onChange={e => setBallotId(e.target.value)}
        />
      </div>

      <button type="button" onClick={handleCompute} disabled={status.loading} className="btn-full">
        {status.loading ? <><span className="spinner" /> Decrypting Tally...</> : '🔓 Compute Tally'}
      </button>
    </div>
  );
}
