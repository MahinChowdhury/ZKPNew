const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

class FabricClient {
  constructor() {
    this.gateway = null;
    this.wallet = null;
    this.contract = null;
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
      
      const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

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
      await this.gateway.connect(ccp, {
        wallet: this.wallet,
        identity: 'appUser',
        discovery: { enabled: true, asLocalhost: true }
      });

      // Get network and contract
      const network = await this.gateway.getNetwork('mychannel');
      this.contract = network.getContract('identity');

      console.log('✅ Connected to Fabric network (identity contract)');
      return this.contract;
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

  // ============================
  // Registration Functions
  // ============================

  /**
   * Register a new voter by adding commitment to the global Merkle tree
   * @param {string} nidHash - Hash of NID (for duplicate check)
   * @param {string} commitment - Poseidon commitment = Poseidon(faceHash, secretKey)
   */
  async registerUser(nidHash, commitment) {
    try {
      const result = await this.contract.submitTransaction('register', nidHash, commitment);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get all registered commitments (for building Merkle tree client-side)
   * @returns {string[]} Array of commitment strings
   */
  async getCommitments() {
    try {
      const result = await this.contract.evaluateTransaction('getCommitments');
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get voter count (number of registered face commitments)
   */
  async getVoterCount() {
    try {
      const result = await this.contract.evaluateTransaction('getVoterCount');
      return parseInt(result.toString());
    } catch (error) {
      throw error;
    }
  }

  // ============================
  // Iris Registration Functions
  // (Independent Merkle tree)
  // ============================

  /**
   * Register a new voter via iris biometric (independent iris Merkle tree)
   * @param {string} nidHash - Hash of NID
   * @param {string} commitment - Poseidon commitment = Poseidon(irisHash, secretKey)
   */
  async registerIrisUser(nidHash, commitment) {
    try {
      const result = await this.contract.submitTransaction('registerIris', nidHash, commitment);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get all registered iris commitments (for building iris Merkle tree)
   * @returns {string[]} Array of iris commitment strings
   */
  async getIrisCommitments() {
    try {
      const result = await this.contract.evaluateTransaction('getIrisCommitments');
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get iris voter count
   */
  async getIrisVoterCount() {
    try {
      const result = await this.contract.evaluateTransaction('getIrisVoterCount');
      return parseInt(result.toString());
    } catch (error) {
      throw error;
    }
  }

  // ============================
  // Voting Functions
  // ============================

  /**
   * Cast a vote with ZK-SNARK proof + nullifier
   * @param {Object} proof - Groth16 proof object
   * @param {string[]} publicSignals - Public signals from the circuit
   * @param {string} nullifier - Nullifier = Poseidon(secretKey, electionId)
   * @param {Array} encryptedVoteVector - Array of homomorphically encrypted votes (one per candidate)
   * @param {string} ballotId - The ballot this vote is for
   */
  async castVote(proof, publicSignals, nullifier, encryptedVoteVector = null, ballotId = '') {
    try {
      const result = await this.contract.submitTransaction(
        'castVote',
        JSON.stringify(proof),
        JSON.stringify(publicSignals),
        nullifier,
        encryptedVoteVector ? JSON.stringify(encryptedVoteVector) : '',
        ballotId
      );
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Check if a nullifier has been used (double-vote check)
   * @param {string} nullifier - The nullifier to check
   * @returns {boolean} true if nullifier already used
   */
  async hasVoted(nullifier) {
    try {
      const result = await this.contract.evaluateTransaction('hasVoted', nullifier);
      return result.toString() === 'true';
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get vote results (tallies)
   */
  async getVoteResults(ballotId = '') {
    try {
      const result = await this.contract.evaluateTransaction('getVoteResults', ballotId);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get a specific vote by ID
   */
  async getVote(voteId) {
    try {
      const result = await this.contract.evaluateTransaction('getVote', voteId);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get total vote count
   */
  async getVoteCount(ballotId = '') {
    try {
      const result = await this.contract.evaluateTransaction('getVoteCount', ballotId);
      return parseInt(result.toString());
    } catch (error) {
      throw error;
    }
  }

  /**
   * Get all votes (for auditing)
   */
  async getAllVotes(ballotId = '') {
    try {
      const result = await this.contract.evaluateTransaction('getAllVotes', ballotId);
      return JSON.parse(result.toString());
    } catch (error) {
      throw error;
    }
  }

  // ============================
  // Legacy Compatibility Functions
  // ============================

  /**
   * Get ring (legacy — returns commitments instead)
   */
  async getRing() {
    const commitments = await this.getCommitments();
    return commitments.map((c, i) => ({ index: i, commitment: c }));
  }

  /**
   * Get ring size (legacy — returns voter count)
   */
  async getRingSize() {
    return await this.getVoterCount();
  }
}

module.exports = FabricClient;