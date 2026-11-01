import React, { useState, useEffect } from 'react';
import { computeTally, getActiveBallot } from './api';

export default function TallyResult() {
  const [ballotId, setBallotId] = useState('');
  const [status, setStatus] = useState({ loading: false, error: null, success: null, data: null });

  useEffect(() => {
    fetchBallot();
  }, []);

  const fetchBallot = async () => {
    try {
      const res = await getActiveBallot();
      if (res && res.ok && res.ballot) {
        setBallotId(res.ballot.id);
      }
    } catch (e) {
      console.warn("Could not fetch active ballot:", e);
    }
  };

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
        setStatus({
          loading: false,
          error: null,
          success: 'Tally computed and decrypted successfully.',
          data: res
        });
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Compute failed.', success: null, data: null });
    }
  };

  const renderResults = (data) => {
    // tallies = per-candidate counts; tally holds the partial decryptions and their proofs
    const results = data.tallies || data.results || data;
    let entries = [];
    
    if (typeof results === 'object' && !Array.isArray(results)) {
      entries = Object.entries(results).filter(([k]) => k !== 'ballotId' && k !== 'ok' && k !== 'totalVotes');
    }

    if (entries.length > 0) {
      const totalVotes = entries.reduce((acc, [, v]) => acc + (Number(v) || 0), 0);
      const maxVotes = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);

      return (
        <div className="tally-container">
          <div className="tally-header">
            <h4>Election Results</h4>
            <span>Total Votes: <strong>{totalVotes}</strong></span>
          </div>
          
          <div>
            {entries.map(([candidate, votes]) => {
              const voteCount = Number(votes) || 0;
              const pct = totalVotes > 0 ? Math.round((voteCount / totalVotes) * 100) : 0;
              const barWidth = Math.round((voteCount / maxVotes) * 100);

              return (
                <div key={candidate} className="tally-row">
                  <div className="tally-row-header">
                    <span>{candidate}</span>
                    <span>{voteCount} votes ({pct}%)</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${barWidth}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      );
    }

    return (
      <div style={{ marginTop: '1rem', background: '#f8fafc', padding: '1rem', borderRadius: '6px' }}>
        <pre style={{ fontSize: '0.85rem' }}>{JSON.stringify(data, null, 2)}</pre>
      </div>
    );
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2>Homomorphic Tally Results</h2>
        <p>Decrypt homomorphically aggregated ciphertexts on the ledger</p>
      </div>

      {status.error && <div className="alert alert-error">{status.error}</div>}
      {status.success && <div className="alert alert-success">{status.success}</div>}

      {status.data && renderResults(status.data)}

      <div className="form-group" style={{ marginTop: '1rem' }}>
        <label>Ballot ID</label>
        <input
          type="text"
          placeholder="Enter ballot ID"
          value={ballotId}
          onChange={e => setBallotId(e.target.value)}
        />
      </div>

      <button type="button" onClick={handleCompute} disabled={status.loading} className="btn-primary btn-full">
        {status.loading ? <><span className="spinner" /> Decrypting Tally...</> : 'Compute & Decrypt Tally'}
      </button>
    </div>
  );
}
