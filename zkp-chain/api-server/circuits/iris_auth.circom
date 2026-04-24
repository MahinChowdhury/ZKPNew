// ============================================================
// iris_auth.circom — ZK-SNARK for iris biometric authentication
// Architecture: Merkle Tree + Nullifier (Semaphore-style)
// Biometric: Hamming Distance on downsampled iris codes
// Stack: Circom 2 + Groth16, Poseidon hash
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/switcher.circom";

// ============================================================
// PoseidonHashChunked
// Hash an n-element array via Poseidon in chunkSize-element
// chunks, then hash the intermediate digests into one value.
// (Reused from face_auth.circom — identical logic)
// ============================================================
template PoseidonHashChunked(n, chunkSize) {
    signal input in[n];
    signal output out;

    var numChunks = n \ chunkSize;  // integer division

    // Step 1: Hash each chunk
    component chunkHashers[numChunks];
    for (var i = 0; i < numChunks; i++) {
        chunkHashers[i] = Poseidon(chunkSize);
        for (var j = 0; j < chunkSize; j++) {
            chunkHashers[i].inputs[j] <== in[i * chunkSize + j];
        }
    }

    // Step 2: Hash all chunk digests together
    component finalHash = Poseidon(numChunks);
    for (var i = 0; i < numChunks; i++) {
        finalHash.inputs[i] <== chunkHashers[i].out;
    }

    out <== finalHash.out;
}

// ============================================================
// MerkleTreeChecker
// Verifies Merkle membership using Poseidon-based binary tree.
// (Reused from face_auth.circom — identical logic)
// ============================================================
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];  // 0 = left, 1 = right

    component hashers[levels];
    component switchers[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== levelHashes[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    // The final hash must equal the root
    root === levelHashes[levels];
}

// ============================================================
// HammingDistance
// Computes Hamming distance between two binary vectors and
// asserts it is strictly less than a threshold.
//
// For binary a[i], b[i]:
//   XOR(a, b) = a + b − 2·a·b
//   HD = Σ XOR(a[i], b[i])
//
// Proves: HD < threshold
// ============================================================
template HammingDistance(n) {
    signal input a[n];         // live iris code bits
    signal input b[n];         // registered iris code bits
    signal input threshold;    // max allowed Hamming distance (exclusive)

    signal output pass;        // 1 if HD < threshold, 0 otherwise

    // 1. Constrain all inputs to binary {0, 1}
    for (var i = 0; i < n; i++) {
        a[i] * (1 - a[i]) === 0;
        b[i] * (1 - b[i]) === 0;
    }

    // 2. Compute XOR and accumulate Hamming distance
    signal ab[n];              // a[i] * b[i]
    signal xorBits[n];         // a[i] XOR b[i]
    signal hammingAccum[n + 1];
    hammingAccum[0] <== 0;

    for (var i = 0; i < n; i++) {
        ab[i] <== a[i] * b[i];
        xorBits[i] <== a[i] + b[i] - 2 * ab[i];
        hammingAccum[i + 1] <== hammingAccum[i] + xorBits[i];
    }

    signal hammingDist <== hammingAccum[n];

    // 3. Assert hammingDist < threshold
    //    Max possible HD = n = 256, threshold max = 256
    //    Need ceil(log2(256+1)) = 9 bits for LessThan
    component lt = LessThan(9);
    lt.in[0] <== hammingDist;
    lt.in[1] <== threshold;

    pass <== lt.out;
}

// ============================================================
// IrisAuth — Main circuit (Merkle + Nullifier architecture)
//
// Proves:
//   1. Pack registered iris bits → Poseidon hash matches irisHash
//   2. commitment = Poseidon(irisHash, secretKey) is in the Merkle tree
//   3. nullifier = Poseidon(secretKey, electionId)
//   4. HammingDistance(liveIris, registeredIris) < hammingThreshold
//
// Parameters:
//   codeSize  — number of bits in downsampled iris code (256)
//   treeLevels — Merkle tree depth (20 → supports ~1M voters)
// ============================================================
template IrisAuth(codeSize, treeLevels) {
    // --- Public Inputs ---
    signal input irisHash;              // Poseidon hash of registered iris code + salt
    signal input merkleRoot;            // Root of the iris commitment Merkle tree
    signal input nullifier;             // Nullifier = Poseidon(secretKey, electionId)
    signal input electionId;            // Unique election identifier
    signal input hammingThreshold;      // Max HD (e.g., 123 for 0.478 * 256)

    // --- Private Inputs ---
    signal input irisCodeLive[codeSize];           // Live iris code bits (0/1)
    signal input irisCodeRegistered[codeSize];     // Registered iris code bits (0/1)
    signal input salt;                             // Salt used during registration
    signal input secretKey;                        // Voter's secret key
    signal input pathElements[treeLevels];         // Merkle proof siblings
    signal input pathIndices[treeLevels];          // Merkle proof path (0=left, 1=right)

    // --- Output ---
    signal output valid;

    // =====================
    // 1. Pack registered iris bits into field elements and hash
    //    256 bits → 32 packed bytes (8 bits each) via Bits2Num
    //    Then PoseidonHashChunked(32, 8): 4 chunks of 8 → Poseidon(4)
    // =====================
    var nPacks = codeSize \ 8;   // = 32

    component packBits[nPacks];
    for (var i = 0; i < nPacks; i++) {
        packBits[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            packBits[i].in[j] <== irisCodeRegistered[i * 8 + j];
        }
    }

    // Hash the 32 packed values
    component irisHasher = PoseidonHashChunked(nPacks, 8);
    for (var i = 0; i < nPacks; i++) {
        irisHasher.in[i] <== packBits[i].out;
    }

    // Combine with salt: finalHash = Poseidon(irisHasher.out, salt)
    component saltHasher = Poseidon(2);
    saltHasher.inputs[0] <== irisHasher.out;
    saltHasher.inputs[1] <== salt;

    // Constrain: computed hash == public irisHash
    saltHasher.out === irisHash;

    // =====================
    // 2. Compute commitment and verify Merkle membership
    //    commitment = Poseidon(irisHash, secretKey)
    // =====================
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== irisHash;
    commitmentHasher.inputs[1] <== secretKey;

    // Verify Merkle tree membership (independent iris tree)
    component merkleChecker = MerkleTreeChecker(treeLevels);
    merkleChecker.leaf <== commitmentHasher.out;
    merkleChecker.root <== merkleRoot;
    for (var i = 0; i < treeLevels; i++) {
        merkleChecker.pathElements[i] <== pathElements[i];
        merkleChecker.pathIndices[i] <== pathIndices[i];
    }

    // =====================
    // 3. Compute and constrain nullifier
    //    nullifier = Poseidon(secretKey, electionId)
    // =====================
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secretKey;
    nullifierHasher.inputs[1] <== electionId;

    nullifierHasher.out === nullifier;

    // =====================
    // 4. Hamming distance check on iris codes
    // =====================
    component hamming = HammingDistance(codeSize);
    for (var i = 0; i < codeSize; i++) {
        hamming.a[i] <== irisCodeLive[i];
        hamming.b[i] <== irisCodeRegistered[i];
    }
    hamming.threshold <== hammingThreshold;

    // All checks must pass
    valid <== hamming.pass;
    valid === 1;
}

// Instantiate with 256-bit downsampled iris codes, 20-level Merkle tree (~1M voters)
// Hamming threshold 0.478 → floor(0.478 × 256) + 1 = 123 (strict less-than)
component main {public [irisHash, merkleRoot, nullifier, electionId, hammingThreshold]} = IrisAuth(256, 20);
