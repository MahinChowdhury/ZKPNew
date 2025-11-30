const { Gateway, Wallets } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
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
      const ccpPath = path.resolve(__dirname, '..', '..', 'test-network', 'organizations', 'peerOrganizations', 'org1.example.com', 'connection-org1.json');
      const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

      // Create wallet
      const walletPath = path.join(process.cwd(), 'wallet');
      this.wallet = await Wallets.newFileSystemWallet(walletPath);

      // Check if admin identity exists
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

      console.log('✅ Connected to Fabric network');
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

  async registerUser(nidHash, Sx, Sy, salt) {
    try {
      const result = await this.contract.submitTransaction('register', nidHash, Sx, Sy, salt);
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to register user: ${error}`);
      throw error;
    }
  }

  async getUserData(nidHash) {
    try {
      const result = await this.contract.evaluateTransaction('getUserData', nidHash);
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to get user data: ${error}`);
      throw error;
    }
  }

  async getAllRegistered() {
    try {
      const result = await this.contract.evaluateTransaction('getAllRegistered');
      return JSON.parse(result.toString());
    } catch (error) {
      console.error(`Failed to get all registered: ${error}`);
      throw error;
    }
  }

  async getRegisteredCount() {
    try {
      const result = await this.contract.evaluateTransaction('getRegisteredCount');
      return parseInt(result.toString());
    } catch (error) {
      console.error(`Failed to get registered count: ${error}`);
      throw error;
    }
  }
}

module.exports = FabricClient;