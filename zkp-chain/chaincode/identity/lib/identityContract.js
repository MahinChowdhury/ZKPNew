'use strict';

const { Contract } = require('fabric-contract-api');

class IdentityContract extends Contract {

  // Initialize ledger
  async initLedger(ctx) {
    console.log('============= START : Initialize Ledger ===========');
    
    // Initialize global face commitments storage
    const commitmentsStore = {
      commitments: [],
      docType: 'commitments'
    };
    await ctx.stub.putState('GLOBAL_COMMITMENTS', Buffer.from(JSON.stringify(commitmentsStore)));

    // Initialize global iris commitments storage (independent Merkle tree)
    const irisCommitmentsStore = {
      commitments: [],
      docType: 'iris_commitments'
    };
    await ctx.stub.putState('GLOBAL_IRIS_COMMITMENTS', Buffer.from(JSON.stringify(irisCommitmentsStore)));
    
    console.log('Identity verification and voting ledger initialized (Merkle + Nullifier, face + iris)');
    console.log('============= END : Initialize Ledger ===========');
  }

  // ============================
  // REGISTRATION FUNCTIONS
  // ============================

  // Register a new voter by adding their Poseidon commitment
  async register(ctx, nidHash, commitment) {
    console.log('============= START : Register Identity ===========');
    
    // Validate inputs
    if (!nidHash || !commitment) {
      throw new Error('All parameters (nidHash, commitment) are required');
    }

    // Check if already registered (by NID)
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
      commitment,
      registeredAt: timestampStr,
      docType: 'identity'
    };

    // Store in ledger (per-user storage for duplicate checking)
    await ctx.stub.putState(nidHash, Buffer.from(JSON.stringify(identity)));

    // Add commitment to global commitments list
    await this._addCommitment(ctx, commitment, timestampStr);

    // Emit registration event
    const eventPayload = {
      nidHash,
      commitment,
      timestamp: timestampStr
    };
    
    await ctx.stub.setEvent('Registered', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Identity registered: ${nidHash}`);
    console.log(`Commitment: ${commitment.slice(0, 20)}...`);
    console.log('============= END : Register Identity ===========');

    return JSON.stringify(identity);
  }

  // Check if user exists
  async userExists(ctx, nidHash) {
    const identityBytes = await ctx.stub.getState(nidHash);
    return identityBytes && identityBytes.length > 0;
  }

  // Helper: Add commitment to global list
  async _addCommitment(ctx, commitment, timestamp) {
    // Get current commitments
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    let store;
    
    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      store = { commitments: [], docType: 'commitments' };
    } else {
      store = JSON.parse(commitmentsBytes.toString());
    }

    // Check for duplicate commitment
    const isDuplicate = store.commitments.some(c => c.value === commitment);
    if (isDuplicate) {
      console.log('Commitment already registered, skipping duplicate');
      return;
    }

    // Add commitment
    store.commitments.push({
      value: commitment,
      registeredAt: timestamp
    });

    // Update store
    await ctx.stub.putState('GLOBAL_COMMITMENTS', Buffer.from(JSON.stringify(store)));
    
    console.log(`Added commitment. Total commitments: ${store.commitments.length}`);
  }

  // Get all registered commitments (for building Merkle tree client-side)
  async getCommitments(ctx) {
    console.log('============= START : Get Commitments ===========');
    
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    
    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return JSON.stringify([]);
    }

    const store = JSON.parse(commitmentsBytes.toString());
    
    console.log(`Commitments count: ${store.commitments.length}`);
    console.log('============= END : Get Commitments ===========');

    // Return only the commitment values
    return JSON.stringify(store.commitments.map(c => c.value));
  }

  // Get voter count (number of registered commitments)
  async getVoterCount(ctx) {
    console.log('============= START : Get Voter Count ===========');
    
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    
    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return 0;
    }

    const store = JSON.parse(commitmentsBytes.toString());
    
    console.log(`Voter count: ${store.commitments.length}`);
    console.log('============= END : Get Voter Count ===========');
    
    return store.commitments.length;
  }

  // ============================
  // IRIS REGISTRATION FUNCTIONS
  // (Independent Merkle tree)
  // ============================

  // Register a new voter via iris biometric
  async registerIris(ctx, nidHash, commitment) {
    console.log('============= START : Register Iris Identity ===========');
    
    if (!nidHash || !commitment) {
      throw new Error('All parameters (nidHash, commitment) are required');
    }

    // Check if already registered with iris (separate key space)
    const irisKey = `IRIS_${nidHash}`;
    const exists = await ctx.stub.getState(irisKey);
    if (exists && exists.length > 0) {
      throw new Error(`Iris identity with NID hash ${nidHash} is already registered`);
    }

    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    const identity = {
      nidHash,
      commitment,
      biometricType: 'iris',
      registeredAt: timestampStr,
      docType: 'iris_identity'
    };

    // Store per-user iris identity
    await ctx.stub.putState(irisKey, Buffer.from(JSON.stringify(identity)));

    // Add commitment to the independent iris commitments list
    await this._addIrisCommitment(ctx, commitment, timestampStr);

    // Emit registration event
    const eventPayload = {
      nidHash,
      commitment,
      biometricType: 'iris',
      timestamp: timestampStr
    };
    await ctx.stub.setEvent('IrisRegistered', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Iris identity registered: ${nidHash}`);
    console.log(`Iris commitment: ${commitment.slice(0, 20)}...`);
    console.log('============= END : Register Iris Identity ===========');

    return JSON.stringify(identity);
  }

  // Helper: Add commitment to global iris list
  async _addIrisCommitment(ctx, commitment, timestamp) {
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_IRIS_COMMITMENTS');
    let store;

    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      store = { commitments: [], docType: 'iris_commitments' };
    } else {
      store = JSON.parse(commitmentsBytes.toString());
    }

    const isDuplicate = store.commitments.some(c => c.value === commitment);
    if (isDuplicate) {
      console.log('Iris commitment already registered, skipping duplicate');
      return;
    }

    store.commitments.push({
      value: commitment,
      registeredAt: timestamp
    });

    await ctx.stub.putState('GLOBAL_IRIS_COMMITMENTS', Buffer.from(JSON.stringify(store)));
    console.log(`Added iris commitment. Total iris commitments: ${store.commitments.length}`);
  }

  // Get all registered iris commitments (for building Merkle tree)
  async getIrisCommitments(ctx) {
    console.log('============= START : Get Iris Commitments ===========');

    const commitmentsBytes = await ctx.stub.getState('GLOBAL_IRIS_COMMITMENTS');

    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return JSON.stringify([]);
    }

    const store = JSON.parse(commitmentsBytes.toString());

    console.log(`Iris commitments count: ${store.commitments.length}`);
    console.log('============= END : Get Iris Commitments ===========');

    return JSON.stringify(store.commitments.map(c => c.value));
  }

  // Get iris voter count
  async getIrisVoterCount(ctx) {
    console.log('============= START : Get Iris Voter Count ===========');

    const commitmentsBytes = await ctx.stub.getState('GLOBAL_IRIS_COMMITMENTS');

    if (!commitmentsBytes || commitmentsBytes.length === 0) {
      return 0;
    }

    const store = JSON.parse(commitmentsBytes.toString());

    console.log(`Iris voter count: ${store.commitments.length}`);
    console.log('============= END : Get Iris Voter Count ===========');

    return store.commitments.length;
  }

  // ============================
  // VOTING FUNCTIONS
  // ============================

  // Cast a vote with ZK-SNARK proof + nullifier
  // The chaincode is completely oblivious to the voter's identity.
  // The nullifier prevents double voting without revealing who voted.
  async castVote(ctx, proofJSON, publicSignalsJSON, nullifier, encryptedVoteJSON, ballotId) {
    console.log('============= START : Cast Vote ===========');
    
    if (!proofJSON || !publicSignalsJSON || !nullifier) {
      throw new Error('Required parameters: proof, publicSignals, nullifier');
    }

    const proof = JSON.parse(proofJSON);
    const publicSignals = JSON.parse(publicSignalsJSON);
    
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

    // Check for double voting using nullifier
    const nullifierKey = `NULLIFIER_${nullifier}`;
    const existingVote = await ctx.stub.getState(nullifierKey);
    
    if (existingVote && existingVote.length > 0) {
      throw new Error('Double voting detected - this identity has already voted');
    }

    // Use txId as the unique, conflict-free vote identifier
    const txId = ctx.stub.getTxID();
    const voteId = `VOTE_${txId}`;

    // Get timestamp
    const txTimestamp = ctx.stub.getTxTimestamp();
    const timestampStr = new Date(txTimestamp.seconds.low * 1000).toISOString();

    // Create vote record — NO plaintext or hashed candidate names stored!
    const vote = {
      voteId,
      ballotId: ballotId || '',
      proof,
      publicSignals,
      nullifier,
      encryptedVote,
      timestamp: timestampStr,
      txId,
      docType: 'vote'
    };

    // Store vote — key is unique per transaction, zero read-write conflict
    await ctx.stub.putState(voteId, Buffer.from(JSON.stringify(vote)));

    // Store nullifier to prevent double voting
    const nullifierRecord = {
      voteId,
      timestamp: timestampStr,
      docType: 'nullifier'
    };
    await ctx.stub.putState(nullifierKey, Buffer.from(JSON.stringify(nullifierRecord)));

    // Emit vote event (without revealing identity or choice)
    const eventPayload = {
      voteId,
      ballotId: ballotId || '',
      hasEncryption: encryptedVote !== null,
      timestamp: timestampStr
    };
    
    await ctx.stub.setEvent('VoteCast', Buffer.from(JSON.stringify(eventPayload)));

    console.log(`Vote cast: ${voteId}`);
    console.log(`Ballot: ${ballotId || 'not specified'}`);
    console.log(`Nullifier: ${nullifier.slice(0, 20)}...`);
    console.log(`Encrypted: ${encryptedVote !== null}`);
    console.log('============= END : Cast Vote ===========');

    return JSON.stringify({
      voteId,
      ballotId: ballotId || '',
      timestamp: timestampStr
    });
  }

  // Check if a nullifier has been used (double-vote check)
  async hasVoted(ctx, nullifier) {
    console.log('============= START : Check Has Voted ===========');
    
    const nullifierKey = `NULLIFIER_${nullifier}`;
    const existingVote = await ctx.stub.getState(nullifierKey);
    
    const hasVoted = existingVote && existingVote.length > 0;
    
    console.log(`Nullifier used: ${hasVoted}`);
    console.log('============= END : Check Has Voted ===========');
    
    return hasVoted;
  }

  // Get vote results (tally)
  async getVoteResults(ctx, ballotId = '') {
    console.log('============= START : Get Vote Results ===========');
    
    let totalVotes = 0;

    const queryString = {
      selector: {
        docType: 'vote'
      }
    };
    
    if (ballotId && ballotId.trim() !== '') {
      queryString.selector.ballotId = ballotId;
    }

    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'vote') {
          totalVotes++;
        }
      } catch (err) {
        console.log('Error parsing record:', err);
      }
      
      result = await iterator.next();
    }
    
    await iterator.close();

    // Get voter count
    const commitmentsBytes = await ctx.stub.getState('GLOBAL_COMMITMENTS');
    let voterCount = 0;
    
    if (commitmentsBytes && commitmentsBytes.length > 0) {
      const store = JSON.parse(commitmentsBytes.toString());
      voterCount = store.commitments.length;
    }

    console.log(`Total votes: ${totalVotes}`);
    console.log(`Voter count: ${voterCount}`);
    console.log('============= END : Get Vote Results ===========');
    
    return JSON.stringify({
      totalVotes,
      tallies: {},
      voterCount
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
  async getVoteCount(ctx, ballotId = '') {
    console.log('============= START : Get Vote Count ===========');

    let count = 0;
    
    const queryString = {
      selector: {
        docType: 'vote'
      }
    };
    
    if (ballotId && ballotId.trim() !== '') {
      queryString.selector.ballotId = ballotId;
    }

    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();
    
    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      try {
        const record = JSON.parse(strValue);
        if (record.docType === 'vote') count++;
      } catch (_) {}
      result = await iterator.next();
    }
    await iterator.close();

    console.log(`Total votes: ${count}`);
    console.log('============= END : Get Vote Count ===========');

    return count;
  }

  // Get all votes (for auditing)
  async getAllVotes(ctx, ballotId = '') {
    console.log('============= START : Get All Votes ===========');
    
    const allVotes = [];
    
    const queryString = {
      selector: {
        docType: 'vote'
      }
    };
    
    if (ballotId && ballotId.trim() !== '') {
      queryString.selector.ballotId = ballotId;
    }

    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
        if (record.docType === 'vote') {
          allVotes.push({
            voteId: record.voteId,
            ballotId: record.ballotId || '',
            nullifier: record.nullifier,
            timestamp: record.timestamp,
            encryptedVote: record.encryptedVote,
            proof: record.proof,
            publicSignals: record.publicSignals
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

  // ============================
  // LEGACY COMPATIBILITY
  // ============================

  // Get user data by nidHash (legacy)
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

    return JSON.stringify({
      commitment: identity.commitment
    });
  }

  // Get all registered identities (legacy)
  async getAllRegistered(ctx) {
    console.log('============= START : Get All Registered ===========');
    
    const allResults = [];
    
    const queryString = {
      selector: {
        docType: 'identity'
      }
    };
    
    const iterator = await ctx.stub.getQueryResult(JSON.stringify(queryString));
    let result = await iterator.next();

    while (!result.done) {
      const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
      
      try {
        const record = JSON.parse(strValue);
        
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

  // Legacy: getRing → returns commitments
  async getRing(ctx) {
    return await this.getCommitments(ctx);
  }

  // Legacy: getRingSize → returns voter count
  async getRingSize(ctx) {
    return await this.getVoterCount(ctx);
  }
}

module.exports = IdentityContract;