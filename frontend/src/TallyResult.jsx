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
         setStatus({ loading: false, error: null, success: 'Tally computed successfully!', data: res });
      }
    } catch (err) {
      setStatus({ loading: false, error: err.message || 'Compute failed.', success: null, data: null });
    }
  };

  return (
    <div className="card">
      <h2 style={{ marginBottom: '1.5rem' }}>Tally Result Management</h2>
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
      
      {status.data && (
        <div style={{ marginBottom: '1rem', padding: '1rem', backgroundColor: 'var(--bg-color)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)', overflowX: 'auto' }}>
          <h4>Result Data:</h4>
          <pre style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
            {JSON.stringify(status.data, null, 2)}
          </pre>
        </div>
      )}

      <div className="form-group">
        <label>Ballot ID</label>
        <input 
          type="text" 
          placeholder="e.g. ballot_1774786248124" 
          value={ballotId} 
          onChange={e => setBallotId(e.target.value)} 
        />
      </div>

      <div style={{ marginTop: '1rem' }}>
        <button type="button" onClick={handleCompute} disabled={status.loading} style={{ width: '100%' }}>
          {status.loading ? 'Processing...' : 'Compute Tally'}
        </button>
      </div>
    </div>
  );
}
