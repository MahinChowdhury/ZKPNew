'use strict';

const { Contract } = require('fabric-contract-api');

class IdentityContract extends Contract {

  // Initialize ledger
  async initLedger(ctx) {
    console.log('============= START : Initialize Ledger ===========');
    
    // Initialize global ring storage for voting
    const ring = {
      publicKeys: [],
      docType: 'ring'
    };
    await ctx.stub.putState('GLOBAL_RING', Buffer.from(JSON.stringify(ring)));
    
    // Initialize vote counter
    const voteCounter = {
      count: 0,
      docType: 'counter'
    };
    await ctx.stub.putState('VOTE_COUNTER', Buffer.from(JSON.stringify(voteCounter)));
    
    console.log('Identity verification and voting ledger initialized');
    console.log('============= END : Initialize Ledger ===========');
  }

  // ============================
  // LEGACY IDENTITY FUNCTIONS
  // (Backward compatibility)
  // ============================

  // Register a new identity (LEGACY - stores per-user)
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

    // Create identity object (LEGACY format)
    const identity = {
      nidHash,
      Sx,
      Sy,
      salt,
      registeredAt: timestampStr,
      docType: 'identity'
    };

    // Store in ledger (per-user storage)
    await ctx.stub.putState(nidHash, Buffer.from(JSON.stringify(identity)));

    // ALSO add to global ring for voting
    await this._addToRing(ctx, Sx, Sy, salt, timestampStr);

    // Emit registration event
    const eventPayload = {
      nidHash,
      Sx,
      Sy,
      salt,
      timestamp: timestampStr
    };
    
    await ctx.stub.setEvent('Registered', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Identity registered: ${nidHash}`);
    console.log('============= END : Register Identity ===========');

    return JSON.stringify(identity);
  }

  // Get user data by nidHash (LEGACY)
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

  // Check if user exists (LEGACY)
  async userExists(ctx, nidHash) {
    const identityBytes = await ctx.stub.getState(nidHash);
    return identityBytes && identityBytes.length > 0;
  }

  // Get all registered identities (LEGACY)
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

  // Get count of registered identities (LEGACY)
  async getRegisteredCount(ctx) {
    console.log('============= START : Get Registered Count ===========');
    
    const allRegistered = await this.getAllRegistered(ctx);
    const results = JSON.parse(allRegistered);
    const count = results.length;
    
    console.log(`Total registered identities: ${count}`);
    console.log('============= END : Get Registered Count ===========');
    
    return count;
  }

  // Get registered identity at specific index (LEGACY)
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

  // Query identity with full details (LEGACY)
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

  // Get transaction history for an identity (LEGACY)
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

  // ============================
  // NEW VOTING FUNCTIONS
  // ============================

  // Helper: Add public key to global ring
  async _addToRing(ctx, Sx, Sy, salt, timestamp) {
    // Get current ring
    const ringBytes = await ctx.stub.getState('GLOBAL_RING');
    let ring;
    
    if (!ringBytes || ringBytes.length === 0) {
      ring = { publicKeys: [], docType: 'ring' };
    } else {
      ring = JSON.parse(ringBytes.toString());
    }

    // Check for duplicate
    const isDuplicate = ring.publicKeys.some(pk => pk.x === Sx && pk.y === Sy);
    if (isDuplicate) {
      console.log('Public key already in ring, skipping duplicate');
      return;
    }

    // Add to ring
    ring.publicKeys.push({
      x: Sx,
      y: Sy,
      salt,
      registeredAt: timestamp
    });

    // Update ring
    await ctx.stub.putState('GLOBAL_RING', Buffer.from(JSON.stringify(ring)));
    
    console.log(`Added to ring. New ring size: ${ring.publicKeys.length}`);
  }

  // Get the global ring (all public keys)
  async getRing(ctx) {
    console.log('============= START : Get Ring ===========');
    
    const ringBytes = await ctx.stub.getState('GLOBAL_RING');
    
    if (!ringBytes || ringBytes.length === 0) {
      return JSON.stringify([]);
    }

    const ring = JSON.parse(ringBytes.toString());
    
    console.log(`Ring size: ${ring.publicKeys.length}`);
    console.log('============= END : Get Ring ===========');

    // Return only the public keys (x, y coordinates)
    return JSON.stringify(ring.publicKeys.map(pk => ({ x: pk.x, y: pk.y })));
  }

  // Get ring size
  async getRingSize(ctx) {
    console.log('============= START : Get Ring Size ===========');
    
    const ringBytes = await ctx.stub.getState('GLOBAL_RING');
    
    if (!ringBytes || ringBytes.length === 0) {
      return 0;
    }

    const ring = JSON.parse(ringBytes.toString());
    
    console.log(`Ring size: ${ring.publicKeys.length}`);
    console.log('============= END : Get Ring Size ===========');
    
    return ring.publicKeys.length;
  }

  // Cast a vote with linkable ring signature
  async castVote(ctx, voteChoiceHash, signatureJSON, ringJSON, encryptedVoteJSON) {
    console.log('============= START : Cast Vote ===========');
    
    if (!voteChoiceHash || !signatureJSON || !ringJSON) {
      throw new Error('Required parameters: voteChoiceHash, signature, ring');
    }

    const signature = JSON.parse(signatureJSON);
    const ring = JSON.parse(ringJSON);
    
    // Parse encrypted vote if provided
    let encryptedVote = null;
    if (encryptedVoteJSON && encryptedVoteJSON.trim() !== '') {
      try {
        encryptedVote = JSON.parse(encryptedVoteJSON);
        console.log('✅ Encrypted vote received and parsed');
      } catch (err) {
        console.log('⚠️  Warning: Could not parse encrypted vote');
      }
    } else {
      console.log('⚠️  Warning: No encrypted vote provided');
    }

    // Extract link tag
    const linkTag = signature.linkTag;
    const linkTagKey = `LINK_TAG_${linkTag.x}_${linkTag.y}`;

    // Check for double voting
    const existingVote = await ctx.stub.getState(linkTagKey);
    
    if (existingVote && existingVote.length > 0) {
      throw new Error('Double voting detected - this identity has already voted');
    }

    // Get vote counter
    const counterBytes = await ctx.stub.getState('VOTE_COUNTER');
    let counter;
    
    if (!counterBytes || counterBytes.length === 0) {
      counter = { count: 0, docType: 'counter' };
    } else {
      counter = JSON.parse(counterBytes.toString());
    }

    // Increment counter
    counter.count += 1;
    const voteId = `VOTE_${counter.count}`;

    // Get timestamp
    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    // Create vote record — NO plaintext voteChoice stored on-chain
    const vote = {
      voteId,
      voteChoiceHash,  // Only the SHA-256 hash of the choice, not the plaintext
      signature,
      ring,
      encryptedVote,  // CRITICAL: This must be included
      timestamp: timestampStr,
      txId: ctx.stub.getTxID(),
      docType: 'vote'
    };

    // Store vote
    await ctx.stub.putState(voteId, Buffer.from(JSON.stringify(vote)));

    // Store link tag to prevent double voting
    const linkTagRecord = {
      voteId,
      timestamp: timestampStr,
      docType: 'linkTag'
    };
    await ctx.stub.putState(linkTagKey, Buffer.from(JSON.stringify(linkTagRecord)));

    // Update counter
    await ctx.stub.putState('VOTE_COUNTER', Buffer.from(JSON.stringify(counter)));

    // Emit vote event (without revealing identity or choice)
    const eventPayload = {
      voteId,
      voteChoiceHash,
      ringSize: ring.length,
      hasEncryption: encryptedVote !== null,
      timestamp: timestampStr
    };
    
    await ctx.stub.setEvent('VoteCast', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Vote cast: ${voteId}`);
    console.log(`Choice hash: ${voteChoiceHash}`);
    console.log(`Encrypted: ${encryptedVote !== null}`);
    console.log('============= END : Cast Vote ===========');

    return JSON.stringify({
      voteId,
      voteChoiceHash,
      timestamp: timestampStr
    });
  }

  // Get vote results (tally)
  async getVoteResults(ctx) {
    console.log('============= START : Get Vote Results ===========');
    
    const tallies = {};
    let totalVotes = 0;

    // Query all votes
    const iterator = await ctx.stub.getStateByRange('', '');
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'vote') {
          totalVotes++;
          
          const choiceHash = record.voteChoiceHash || record.voteChoice || 'unknown';
          if (tallies[choiceHash]) {
            tallies[choiceHash]++;
          } else {
            tallies[choiceHash] = 1;
          }
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();

    // Get ring size
    const ringBytes = await ctx.stub.getState('GLOBAL_RING');
    let ringSize = 0;
    
    if (ringBytes && ringBytes.length > 0) {
      const ring = JSON.parse(ringBytes.toString());
      ringSize = ring.publicKeys.length;
    }

    console.log(`Total votes: ${totalVotes}`);
    console.log(`Ring size: ${ringSize}`);
    console.log('============= END : Get Vote Results ===========');
    
    return JSON.stringify({
      totalVotes,
      tallies,
      ringSize
    });
  }

  // Get a specific vote (for verification)
  async getVote(ctx, voteId) {
    console.log('============= START : Get Vote ===========');
    
    if (!voteId) {
      throw new Error('Vote ID is required');
    }

    const voteBytes = await ctx.stub.getState(voteId);
    
    if (!voteBytes || voteBytes.length === 0) {
      throw new Error(`Vote ${voteId} does not exist`);
    }

    const vote = JSON.parse(voteBytes.toString());
    
    console.log('============= END : Get Vote ===========');
    
    return JSON.stringify(vote);
  }

  // Get vote count
  async getVoteCount(ctx) {
    console.log('============= START : Get Vote Count ===========');
    
    const counterBytes = await ctx.stub.getState('VOTE_COUNTER');
    
    if (!counterBytes || counterBytes.length === 0) {
      return 0;
    }

    const counter = JSON.parse(counterBytes.toString());
    
    console.log(`Total votes: ${counter.count}`);
    console.log('============= END : Get Vote Count ===========');
    
    return counter.count;
  }

  // Check if link tag has been used (double-vote check)
  async hasVoted(ctx, linkTagX, linkTagY) {
    console.log('============= START : Check Has Voted ===========');
    
    const linkTagKey = `LINK_TAG_${linkTagX}_${linkTagY}`;
    const existingVote = await ctx.stub.getState(linkTagKey);
    
    const hasVoted = existingVote && existingVote.length > 0;
    
    console.log(`Link tag voted: ${hasVoted}`);
    console.log('============= END : Check Has Voted ===========');
    
    return hasVoted;
  }

  // Get all votes (for auditing) - FIXED TO INCLUDE ENCRYPTED VOTES
  async getAllVotes(ctx) {
    console.log('============= START : Get All Votes ===========');
    
    const allVotes = [];
    const iterator = await ctx.stub.getStateByRange('', '');
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'vote') {
          // Return vote data with hash (no plaintext choice on-chain)
          allVotes.push({
            voteId: record.voteId,
            voteChoiceHash: record.voteChoiceHash || record.voteChoice,  // backward compat
            timestamp: record.timestamp,
            ringSize: record.ring ? record.ring.length : 0,
            encryptedVote: record.encryptedVote,
            signature: record.signature,
            ring: record.ring
          });
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();
    
    console.log(`Found ${allVotes.length} votes`);
    console.log(`Votes with encryption: ${allVotes.filter(v => v.encryptedVote !== null).length}`);
    console.log('============= END : Get All Votes ===========');
    
    return JSON.stringify(allVotes);
  }
}

module.exports = IdentityContract;