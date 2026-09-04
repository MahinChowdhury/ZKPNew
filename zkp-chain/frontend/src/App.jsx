import React, { useState, useEffect } from 'react';
import './App.css';

import Register from './Register';
import BallotManagement from './BallotManagement';
import VoteCasting from './VoteCasting';
import TallyResult from './TallyResult';
import { getSystemHealth } from './api';

function App() {
  const [currentView, setCurrentView] = useState('register');
  const [health, setHealth] = useState(null);

  useEffect(() => {
    fetchHealth();
    const timer = setInterval(fetchHealth, 10000);
    return () => clearInterval(timer);
  }, []);

  const fetchHealth = async () => {
    const data = await getSystemHealth();
    if (data && data.ok) {
      setHealth(data);
    }
  };

  return (
    <div className="app-container">
      {/* Top System Status Bar */}
      <div className="system-health-bar">
        <div className="health-content">
          <div className="health-status">
            <span className={health ? "dot-online" : "dot-offline"} />
            <span>Fabric Ledger: {health ? 'Connected' : 'Connecting...'}</span>
          </div>
          <div className="health-metrics">
            <span className="metric-item">Face Voters: <strong>{health?.registeredVoters?.face ?? 0}</strong></span>
            <span className="metric-item">Iris Voters: <strong>{health?.registeredVoters?.iris ?? 0}</strong></span>
            <span className="metric-item">Total Votes: <strong>{health?.totalVotes ?? 0}</strong></span>
          </div>
        </div>
      </div>

      <div className="container">
        {/* Header */}
        <header className="app-header">
          <h1>Biometric Zero-Knowledge Voting</h1>
          <p>Decentralized e-voting protocol built on Hyperledger Fabric and Groth16 zk-SNARKs</p>
        </header>

        {/* Navigation Tabs */}
        <div className="nav-tabs">
          <button
            type="button"
            className={`nav-tab ${currentView === 'register' ? 'active' : ''}`}
            onClick={() => setCurrentView('register')}
          >
            Register
          </button>
          <button
            type="button"
            className={`nav-tab ${currentView === 'ballot' ? 'active' : ''}`}
            onClick={() => setCurrentView('ballot')}
          >
            Create Election
          </button>
          <button
            type="button"
            className={`nav-tab ${currentView === 'vote' ? 'active' : ''}`}
            onClick={() => setCurrentView('vote')}
          >
            Cast Vote
          </button>
          <button
            type="button"
            className={`nav-tab ${currentView === 'tally' ? 'active' : ''}`}
            onClick={() => setCurrentView('tally')}
          >
            Tally Results
          </button>
        </div>

        {/* Main Content View */}
        <main>
          {currentView === 'register' && <Register onRegistrationSuccess={fetchHealth} />}
          {currentView === 'ballot' && <BallotManagement onBallotUpdated={fetchHealth} />}
          {currentView === 'vote' && <VoteCasting onVoteSuccess={fetchHealth} />}
          {currentView === 'tally' && <TallyResult />}
        </main>
      </div>
    </div>
  );
}

export default App;
