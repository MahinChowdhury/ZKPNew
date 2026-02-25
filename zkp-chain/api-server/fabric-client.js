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
      console.error(`Failed to connect to Fabric network: ${error}`);
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
   * Register a new voter by adding public key to global ring
   * @param {string} nidHash - Hash of NID (for legacy compatibility)
   * @param {string} Sx - X coordinate of public key S = k·G
   * @param {string} Sy - Y coordinate of public key S = k·G
   * @param {string} salt - Salt used in key derivation
   */
  async registerUser(nidHash, Sx, Sy, salt) {
    try {
      const result = await this.contract.submitTransaction('register', nidHash, Sx, Sy, salt);
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to register user: ${error}`);
      throw error;
    }
  }

  /**
   * Get the global ring (all registered public keys)
   * @returns {Array<{x: string, y: string}>} Array of public keys
   */
  async getRing() {
    try {
      const result = await this.contract.evaluateTransaction('getRing');
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to get ring: ${error}`);
      throw error;
    }
  }

  /**
   * Get ring size (number of registered voters)
   */
  async getRingSize() {
    try {
      const result = await this.contract.evaluateTransaction('getRingSize');
      return parseInt(result.toString());
    } catch (error) {
      console.error(`Failed to get ring size: ${error}`);
      throw error;
    }
  }

  // ============================
  // Voting Functions
  // ============================

  /**
   * Cast a vote with linkable ring signature
   * @param {string} voteChoice - The vote choice (e.g., "Candidate A")
   * @param {Object} signature - LRS signature { c0, s[], linkTag }
   * @param {Array} ring - Ring of public keys at time of signing
   * @param {Object} encryptedVote - Homomorphically encrypted vote (optional)
   */
  async castVote(voteChoice, signature, ring, encryptedVote = null) {
    try {
      const result = await this.contract.submitTransaction(
        'castVote',
        voteChoice,
        JSON.stringify(signature),
        JSON.stringify(ring),
        encryptedVote ? JSON.stringify(encryptedVote) : ''
      );
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to cast vote: ${error}`);
      throw error;
    }
  }

  /**
   * Get vote results (tallies)
   */
  async getVoteResults() {
    try {
      const result = await this.contract.evaluateTransaction('getVoteResults');
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to get vote results: ${error}`);
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
      console.error(`Failed to get vote: ${error}`);
      throw error;
    }
  }

  /**
   * Get total vote count
   */
  async getVoteCount() {
    try {
      const result = await this.contract.evaluateTransaction('getVoteCount');
      return parseInt(result.toString());
    } catch (error) {
      console.error(`Failed to get vote count: ${error}`);
      throw error;
    }
  }

  /**
   * Get all votes (for auditing)
   */
  async getAllVotes() {
    try {
      const result = await this.contract.evaluateTransaction('getAllVotes');
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to get all votes: ${error}`);
      throw error;
    }
  }

  /**
   * Check if a link tag has been used (double-vote check)
   */
  async hasVoted(linkTagX, linkTagY) {
    try {
      const result = await this.contract.evaluateTransaction('hasVoted', linkTagX, linkTagY);
      return result.toString() === 'true';
    } catch (error) {
      console.error(`Failed to check voting status: ${error}`);
      throw error;
    }
  }

  // ============================
  // Legacy Compatibility Functions
  // ============================

  /**
   * Get user data by nidHash (legacy - for backward compatibility)
   * Note: In the new system, we don't store per-user data
   */
  async getUserData(nidHash) {
    // This is kept for backward compatibility with existing login endpoints
    // In practice, the ring signature system doesn't need this
    throw new Error('getUserData is deprecated - use getRing() instead');
  }

  /**
   * Get all registered identities (legacy)
   */
  async getAllRegistered() {
    try {
      const ring = await this.getRing();
      return ring.map((pk, index) => `voter_${index}`);
    } catch (error) {
      console.error(`Failed to get registered users: ${error}`);
      throw error;
    }
  }

  /**
   * Get registered count (legacy)
   */
  async getRegisteredCount() {
    try {
      return await this.getRingSize();
    } catch (error) {
      console.error(`Failed to get registered count: ${error}`);
      throw error;
    }
  }
}

module.exports = FabricClient;