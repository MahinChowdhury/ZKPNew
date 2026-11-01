const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

class FabricClient {
  constructor() {
    this.gateway = null;
    this.wallet = null;
    this.contracts = new Map(); // channelName -> contract
    this.ccp = null;
    this.numChannels = 4; // Default partition scale for national workload (multi-channel parallelization)
  }

  async connect() {
    try {
      // Path to test-network
      const ccpPath = path.resolve(
        __dirname,
        '..',
        '..',
        'test-network',
        'organizations',
        'peerOrganizations',
        'org1.example.com',
        'connection-org1.json'
      );
      
      this.ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

      // Create wallet
      const walletPath = path.join(process.cwd(), 'wallet');
      this.wallet = await Wallets.newFileSystemWallet(walletPath);

      // Check if user identity exists
      const identity = await this.wallet.get('appUser');
      if (!identity) {
        console.log('An identity for the user "appUser" does not exist in the wallet');
        console.log('Run the enrollUser.js application before retrying');
        throw new Error('User identity not found in wallet');
      }

      // Connect to gateway
      this.gateway = new Gateway();
      await this.gateway.connect(this.ccp, {
        wallet: this.wallet,
        identity: 'appUser',
        discovery: { enabled: true, asLocalhost: true }
      });

      // Connect default channel for backward compatibility
      try {
        const network = await this.gateway.getNetwork('mychannel');
        const contract = network.getContract('identity');
        this.contracts.set('mychannel', contract);
      } catch (err) {
        console.warn('⚠️ Default mychannel connection failed:', err.message);
      }

      console.log('✅ Connected to Fabric network gateway');
      return this.contracts.get('mychannel');
    } catch (error) {
      throw error;
    }
  }

  async disconnect() {
    if (this.gateway) {
      await this.gateway.disconnect();
      console.log('Disconnected from Fabric network');
    }
  }

  /**
   * Helper to retrieve or establish a contract connection for a specific channel name.
   * Seamlessly falls back to default 'mychannel' for backward compatibility on standard environments.
   */
  async getContract(channelName) {
    if (this.contracts.has(channelName)) {
      return this.contracts.get(channelName);
    }
    if (!this.gateway) {
      throw new Error('FabricClient not connected. Call connect() first.');
    }
    try {
      const network = await this.gateway.getNetwork(channelName);
      const contract = network.getContract('identity');
      this.contracts.set(channelName, contract);
      return contract;
    } catch (err) {
      console.warn(`⚠️ Dynamic channel '${channelName}' not reachable: ${err.message}. Falling back to default 'mychannel'.`);
      const defaultContract = this.contracts.get('mychannel');
      if (!defaultContract) {
        throw new Error(`Dynamic channel '${channelName}' and default 'mychannel' are both unavailable.`);
      }
      // Remember the fallback, so later calls don't retry channel discovery
      this.contracts.set(channelName, defaultContract);
      return defaultContract;
    }
  }

  /**
   * Helper to route a transaction to a partition channel based on a routing key (NID hash, Nullifier, etc.).
   */
  routeChannel(routingKey) {
    if (!routingKey) return 'mychannel';
    let hash = 0;
    for (let i = 0; i < routingKey.length; i++) {
      hash = (hash << 5) - hash + routingKey.charCodeAt(i);
      hash |= 0;
    }
    const index = Math.abs(hash) % this.numChannels;
    return `channel-${index}`;
  }

  // ============================
  // Registration Functions
  // ============================

  /**
   * Register a new voter by adding commitment to the global Merkle tree.
   * enrollProofJSON / enrollSignalsJSON: attested-enrollment proof (enroll_auth.circom)
   */
  async registerUser(nidHash, commitment, enrollProofJSON, enrollSignalsJSON) {
    try {
      const channel = this.routeChannel(nidHash);
      const contract = await this.getContract(channel);
      const result = await contract.submitTransaction('register', nidHash, commitment, enrollProofJSON, enrollSignalsJSON);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get all registered commitments (aggregates across dynamic partition channels for national scale)
   */
  async getCommitments() {
    try {
      let commitments = [];
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          // If we fallback to 'mychannel', prevent duplicate pulls
          if (contract === this.contracts.get('mychannel') && i > 0) continue;
          
          const result = await contract.evaluateTransaction('getCommitments');
          commitments = commitments.concat(JSON.parse(result.toString()));
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getCommitments');
            return JSON.parse(result.toString());
          }
        }
      }
      return commitments;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get voter count (aggregates across partition channels)
   */
  async getVoterCount() {
    try {
      let count = 0;
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          if (contract === this.contracts.get('mychannel') && i > 0) continue;
          
          const result = await contract.evaluateTransaction('getVoterCount');
          count += parseInt(result.toString());
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getVoterCount');
            return parseInt(result.toString());
          }
        }
      }
      return count;
    } catch (error) {
      throw error;
    }
  }

  // ============================
  // Iris Registration Functions
  // ============================

  /**
   * Register a new voter via iris biometric
   */
  async registerIrisUser(nidHash, commitment) {
    try {
      const channel = this.routeChannel(nidHash);
      const contract = await this.getContract(channel);
      const result = await contract.submitTransaction('registerIris', nidHash, commitment);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get all registered iris commitments (aggregates across channels)
   */
  async getIrisCommitments() {
    try {
      let commitments = [];
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          if (contract === this.contracts.get('mychannel') && i > 0) continue;

          const result = await contract.evaluateTransaction('getIrisCommitments');
          commitments = commitments.concat(JSON.parse(result.toString()));
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getIrisCommitments');
            return JSON.parse(result.toString());
          }
        }
      }
      return commitments;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get iris voter count
   */
  async getIrisVoterCount() {
    try {
      let count = 0;
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          if (contract === this.contracts.get('mychannel') && i > 0) continue;

          const result = await contract.evaluateTransaction('getIrisVoterCount');
          count += parseInt(result.toString());
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getIrisVoterCount');
            return parseInt(result.toString());
          }
        }
      }
      return count;
    } catch (error) {
      throw error;
    }
  }

  // ============================
  // Voting Functions
  // ============================

  // ============================
  // Ballot Functions
  // ============================

  async _allContracts() {
    const names = ['mychannel', ...Array.from({ length: this.numChannels }, (_, i) => `channel-${i}`)];
    const contracts = new Set();
    for (const name of names) contracts.add(await this.getContract(name));
    return contracts;
  }

  // Ballot setup runs on every reachable channel (votes are routed by
  // nullifier, and castVote checks the ballot record of its own channel).
  // The same dealings give the same election key on every channel.
  async _submitEverywhere(fn, ...args) {
    let result;
    for (const contract of await this._allContracts()) {
      result = await contract.submitTransaction(fn, ...args);
    }
    return result ? JSON.parse(result.toString()) : null;
  }

  /** Register a ballot with its trustee signing keys and threshold t. */
  async registerBallot(ballotId, numOptions, trustees, threshold) {
    return this._submitEverywhere('registerBallot', ballotId, String(numOptions), JSON.stringify(trustees), String(threshold));
  }

  async submitDealing(ballotId, dealer, commitments, sig) {
    return this._submitEverywhere('submitDealing', ballotId, String(dealer), JSON.stringify(commitments), sig);
  }

  async complain(ballotId, complainer, dealer, share, sig) {
    return this._submitEverywhere('complain', ballotId, String(complainer), String(dealer), share, sig);
  }

  async finalizeBallotKey(ballotId) {
    return this._submitEverywhere('finalizeBallotKey', ballotId);
  }

  async closeBallot(ballotId) {
    return this._submitEverywhere('closeBallot', ballotId);
  }

  // The tally is verified against the ballots of one channel; combining
  // per-channel tallies is future work (FINDINGS C21).
  async publishTally(ballotId, tally) {
    const contract = await this.getContract('mychannel');
    const result = await contract.submitTransaction('publishTally', ballotId, JSON.stringify(tally));
    return JSON.parse(result.toString());
  }

  async getTally(ballotId) {
    const contract = await this.getContract('mychannel');
    const result = await contract.evaluateTransaction('getTally', ballotId);
    return JSON.parse(result.toString());
  }

  /**
   * Register a capture device's EdDSA public key on every reachable channel
   * (castVote checks the registry root on the channel it runs on).
   */
  async registerSensor(ax, ay) {
    return this._submitEverywhere('registerSensor', ax, ay);
  }

  async getSensors() {
    const contract = await this.getContract('mychannel');
    const result = await contract.evaluateTransaction('getSensors');
    return JSON.parse(result.toString());
  }

  /**
   * Fetch the on-chain ballot record { ballotId, numOptions, trustees, threshold,
   * dealings, qual, publicKey, status, electionId }
   */
  async getBallot(ballotId) {
    const contract = await this.getContract('mychannel');
    const result = await contract.evaluateTransaction('getBallot', ballotId);
    return JSON.parse(result.toString());
  }

  /**
   * Cast a vote with ZK-SNARK proof + nullifier
   */
  async castVote(proof, publicSignals, nullifier, encryptedVoteVector = null, ballotId = '', biometricType = 'face') {
    try {
      const channel = this.routeChannel(nullifier);
      const contract = await this.getContract(channel);
      const result = await contract.submitTransaction(
        'castVote',
        JSON.stringify(proof),
        JSON.stringify(publicSignals),
        nullifier,
        encryptedVoteVector ? JSON.stringify(encryptedVoteVector) : '',
        ballotId,
        biometricType
      );
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Check if a nullifier has been used (double-vote check routed to target channel partition)
   */
  async hasVoted(nullifier) {
    try {
      const channel = this.routeChannel(nullifier);
      const contract = await this.getContract(channel);
      const result = await contract.evaluateTransaction('hasVoted', nullifier);
      return result.toString() === 'true';
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get vote results (aggregates tallies across channels)
   */
  async getVoteResults(ballotId = '') {
    try {
      let totalVotes = 0;
      let totalVoterCount = 0;
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          if (contract === this.contracts.get('mychannel') && i > 0) continue;

          const result = await contract.evaluateTransaction('getVoteResults', ballotId);
          const parsed = JSON.parse(result.toString());
          totalVotes += parsed.totalVotes || 0;
          totalVoterCount += parsed.voterCount || 0;
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getVoteResults', ballotId);
            return JSON.parse(result.toString());
          }
        }
      }
      return {
        totalVotes,
        tallies: {},
        voterCount: totalVoterCount
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get a specific vote by ID (check target partition)
   */
  async getVote(voteId) {
    try {
      const channel = this.routeChannel(voteId);
      const contract = await this.getContract(channel);
      const result = await contract.evaluateTransaction('getVote', voteId);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get total vote count (aggregates across channels)
   */
  async getVoteCount(ballotId = '') {
    try {
      let count = 0;
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          if (contract === this.contracts.get('mychannel') && i > 0) continue;

          const result = await contract.evaluateTransaction('getVoteCount', ballotId);
          count += parseInt(result.toString());
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getVoteCount', ballotId);
            return parseInt(result.toString());
          }
        }
      }
      return count;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get all votes (aggregates across channels for auditing)
   */
  async getAllVotes(ballotId = '') {
    try {
      let allVotes = [];
      for (let i = 0; i < this.numChannels; i++) {
        const channelName = `channel-${i}`;
        try {
          const contract = await this.getContract(channelName);
          if (contract === this.contracts.get('mychannel') && i > 0) continue;

          const result = await contract.evaluateTransaction('getAllVotes', ballotId);
          allVotes = allVotes.concat(JSON.parse(result.toString()));
        } catch (err) {
          if (i === 0) {
            const defaultContract = await this.getContract('mychannel');
            const result = await defaultContract.evaluateTransaction('getAllVotes', ballotId);
            return JSON.parse(result.toString());
          }
        }
      }
      return allVotes;
    } catch (error) {
      throw error;
    }
  }

  // ============================
  // Legacy Compatibility Functions
  // ============================

  async getRing() {
    const commitments = await this.getCommitments();
    return commitments.map((c, i) => ({ index: i, commitment: c }));
  }

  async getRingSize() {
    return await this.getVoterCount();
  }
}

module.exports = FabricClient;