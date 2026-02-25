'use strict';

const { Contract } = require('fabric-contract-api');

class IdentityContract extends Contract {

  // Initialize ledger
  async initLedger(ctx) {
    console.log('============= START : Initialize Ledger ===========');
    console.log('Identity verification ledger initialized');
    console.log('============= END : Initialize Ledger ===========');
  }

  // Register a new identity
  async register(ctx, nidHash, Sx, Sy, salt) {
    console.log('============= START : Register Identity ===========');
    
    // Validate inputs
    if (!nidHash || !Sx || !Sy || !salt) {
      throw new Error('All parameters (nidHash, Sx, Sy, salt) are required');
    }

    // Check if already registered
    const exists = await this.userExists(ctx, nidHash);
    if (exists) {
      throw new Error(`Identity with NID hash ${nidHash} is already registered`);
    }

    // Get deterministic timestamp from transaction
    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    // Create identity object
    const identity = {
      nidHash,
      Sx,
      Sy,
      salt,
      registeredAt: timestampStr,
      docType: 'identity'
    };

    // Store in ledger
    await ctx.stub.putState(nidHash, Buffer.from(JSON.stringify(identity)));

    // Emit registration event
    const eventPayload = {
      nidHash,
      Sx,
      Sy,
      salt,
      timestamp: identity.registeredAt
    };
    
    await ctx.stub.setEvent('Registered', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Identity registered: ${nidHash}`);
    console.log('============= END : Register Identity ===========');

    return JSON.stringify(identity);
  }

  // Get user data by nidHash
  async getUserData(ctx, nidHash) {
    console.log('============= START : Get User Data ===========');
    
    if (!nidHash) {
      throw new Error('NID hash is required');
    }

    const identityBytes = await ctx.stub.getState(nidHash);
    
    if (!identityBytes || identityBytes.length === 0) {
      throw new Error(`Identity with NID hash ${nidHash} does not exist`);
    }

    const identity = JSON.parse(identityBytes.toString());
    
    console.log(`Retrieved identity: ${nidHash}`);
    console.log('============= END : Get User Data ===========');

    // Return only the public key components and salt
    return JSON.stringify({
      Sx: identity.Sx,
      Sy: identity.Sy,
      salt: identity.salt
    });
  }

  // Check if user exists
  async userExists(ctx, nidHash) {
    const identityBytes = await ctx.stub.getState(nidHash);
    return identityBytes && identityBytes.length > 0;
  }

  // Get all registered identities (returns array of nidHashes)
  async getAllRegistered(ctx) {
    console.log('============= START : Get All Registered ===========');
    
    const allResults = [];
    
    // Get all states from ledger
    const iterator = await ctx.stub.getStateByRange('', '');
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        // Only include documents of type 'identity'
        if (record.docType === 'identity') {
          allResults.push(record.nidHash);
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();
    
    console.log(`Found ${allResults.length} registered identities`);
    console.log('============= END : Get All Registered ===========');
    
    return JSON.stringify(allResults);
  }

  // Get count of registered identities
  async getRegisteredCount(ctx) {
    console.log('============= START : Get Registered Count ===========');
    
    const allRegistered = await this.getAllRegistered(ctx);
    const results = JSON.parse(allRegistered);
    const count = results.length;
    
    console.log(`Total registered identities: ${count}`);
    console.log('============= END : Get Registered Count ===========');
    
    return count;
  }

  // Get registered identity at specific index
  async getRegisteredAt(ctx, index) {
    console.log('============= START : Get Registered At Index ===========');
    
    const indexNum = parseInt(index);
    
    if (isNaN(indexNum) || indexNum < 0) {
      throw new Error('Index must be a valid non-negative number');
    }

    const allRegistered = await this.getAllRegistered(ctx);
    const results = JSON.parse(allRegistered);
    
    if (indexNum >= results.length) {
      throw new Error(`Index ${indexNum} is out of bounds. Total registered: ${results.length}`);
    }
    
    const nidHash = results[indexNum];
    
    console.log(`Identity at index ${indexNum}: ${nidHash}`);
    console.log('============= END : Get Registered At Index ===========');
    
    return nidHash;
  }

  // Query identity with full details (for admin/debugging)
  async queryIdentity(ctx, nidHash) {
    console.log('============= START : Query Identity ===========');
    
    if (!nidHash) {
      throw new Error('NID hash is required');
    }

    const identityBytes = await ctx.stub.getState(nidHash);
    
    if (!identityBytes || identityBytes.length === 0) {
      throw new Error(`Identity with NID hash ${nidHash} does not exist`);
    }

    const identity = JSON.parse(identityBytes.toString());
    
    console.log('============= END : Query Identity ===========');
    
    return JSON.stringify(identity);
  }

  // Get transaction history for an identity
  async getIdentityHistory(ctx, nidHash) {
    console.log('============= START : Get Identity History ===========');
    
    if (!nidHash) {
      throw new Error('NID hash is required');
    }

    const historyIterator = await ctx.stub.getHistoryForKey(nidHash);
    const history = [];

    let result = await historyIterator.next();
    
    while (!result.done) {
      if (result.value) {
        const record = {
          txId: result.value.txId,
          timestamp: result.value.timestamp,
          isDelete: result.value.isDelete,
          value: result.value.value.toString('utf8')
        };
        
        history.push(record);
      }
      
      result = await historyIterator.next();
    }
    
    await historyIterator.close();
    
    console.log(`Found ${history.length} history records`);
    console.log('============= END : Get Identity History ===========');
    
    return JSON.stringify(history);
  }
}

module.exports = IdentityContract;