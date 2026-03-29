import React, { useState } from 'react';
import './App.css';

import Register from './Register';
import BallotManagement from './BallotManagement';
import VoteCasting from './VoteCasting';
import TallyResult from './TallyResult';

function App() {
  const [currentView, setCurrentView] = useState('register');

  const renderView = () => {
    switch (currentView) {
      case 'register':
        return <Register />;
      case 'ballot':
        return <BallotManagement />;
      case 'vote':
        return <VoteCasting />;
      case 'tally':
        return <TallyResult />;
      default:
        return <Register />;
    }
  };

  return (
    <div className="container App">
      <header style={{ marginBottom: '2rem', textAlign: 'center' }}>
        <h1 style={{ color: 'var(--primary-color)', fontSize: '2.5rem' }}>ZKP Voting System</h1>
        <p>A secure, decentralized voting platform built on ZK-SNARKs</p>
      </header>

      <nav>
        <button 
          className={`nav-link ${currentView === 'register' ? 'active' : ''}`}
          onClick={() => setCurrentView('register')}
        >
          Register User
        </button>
        <button 
          className={`nav-link ${currentView === 'ballot' ? 'active' : ''}`}
          onClick={() => setCurrentView('ballot')}
        >
          Create Ballot
        </button>
        <button 
          className={`nav-link ${currentView === 'vote' ? 'active' : ''}`}
          onClick={() => setCurrentView('vote')}
        >
          Cast Vote
        </button>
        <button 
          className={`nav-link ${currentView === 'tally' ? 'active' : ''}`}
          onClick={() => setCurrentView('tally')}
        >
          Tally Results
        </button>
      </nav>

      <main>
        {renderView()}
      </main>
    </div>
  );
}

export default App;
