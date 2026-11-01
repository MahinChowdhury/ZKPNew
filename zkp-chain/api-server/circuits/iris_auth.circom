// ============================================================
// iris_auth.circom — ZK-SNARK for iris biometric authentication
// Architecture: Merkle Tree + Nullifier (Semaphore-style)
//               + in-circuit sensor attestation of the live sample
// Biometric: Hamming Distance on downsampled iris codes
// Stack: Circom 2 + Groth16, Poseidon hash, EdDSA-Poseidon (BabyJubJub)
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "common.circom";

// ============================================================
// PackedBitsHash
// 256 bits → 32 bytes (Bits2Num(8), LSB first) → PoseidonHashChunked(32, 8)
// ============================================================
template PackedBitsHash(codeSize) {
    signal input bits[codeSize];
    signal output out;

    var nPacks = codeSize \ 8;
    component packBits[nPacks];
    component hasher = PoseidonHashChunked(nPacks, 8);
    for (var i = 0; i < nPacks; i++) {
        packBits[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            packBits[i].in[j] <== bits[i * 8 + j];
        }
        hasher.in[i] <== packBits[i].out;
    }
    out <== hasher.out;
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
// Proves: HD < threshold  (threshold is a template parameter, fixed
// by the verification key — never a prover-chosen input)
// ============================================================
template HammingDistance(n, threshold) {
    signal input a[n];         // live iris code bits
    signal input b[n];         // registered iris code bits

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
//   1. irisHash = Poseidon(pack(registeredIris) || salt)   (private)
//   2. commitment = Poseidon(irisHash, secretKey) is in the Merkle tree
//   3. nullifier = Poseidon(secretKey, electionId)
//   4. HammingDistance(liveIris, registeredIris) < hammingThreshold
//   5. the live code was signed by an authorised capture device for
//      this vote (SensorAttestation)
//   6. the proof is bound to voteBinding (hash of the ballot ciphertexts)
//
// irisHash is deliberately NOT public: it is constant per voter, so
// publishing it would link every ballot a voter casts across elections.
//
// Parameters:
//   codeSize  — number of bits in downsampled iris code (256)
//   treeLevels — Merkle tree depth (20 → supports ~1M voters)
//   hammingThreshold — max HD, exclusive (123 for 0.478 * 256)
//   sensorLevels — sensor registry depth (10 → 1,024 capture devices)
// ============================================================
template IrisAuth(codeSize, treeLevels, hammingThreshold, sensorLevels) {
    // --- Public Inputs ---
    signal input merkleRoot;            // Root of the iris commitment Merkle tree
    signal input nullifier;             // Nullifier = Poseidon(secretKey, electionId)
    signal input electionId;            // Unique election identifier
    signal input voteBinding;           // H(ballot ciphertexts), checked by the chaincode
    signal input sensorRoot;            // Root of the authorised-sensor registry

    // --- Private Inputs ---
    signal input irisCodeLive[codeSize];           // Live iris code bits (0/1)
    signal input irisCodeRegistered[codeSize];     // Registered iris code bits (0/1)
    signal input salt;                             // Salt used during registration
    signal input secretKey;                        // Voter's secret key
    signal input pathElements[treeLevels];         // Merkle proof siblings
    signal input pathIndices[treeLevels];          // Merkle proof path (0=left, 1=right)

    // Sensor attestation (see common.circom)
    signal input sessionNonce;
    signal input sensorAx;
    signal input sensorAy;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input sensorPathElements[sensorLevels];
    signal input sensorPathIndices[sensorLevels];

    // --- Output ---
    signal output valid;

    // =====================
    // 1. irisHash = Poseidon(pack(registered) || salt)
    // =====================
    component registeredHash = PackedBitsHash(codeSize);
    for (var i = 0; i < codeSize; i++) {
        registeredHash.bits[i] <== irisCodeRegistered[i];
    }

    component saltHasher = Poseidon(2);
    saltHasher.inputs[0] <== registeredHash.out;
    saltHasher.inputs[1] <== salt;

    // =====================
    // 2. Compute commitment and verify Merkle membership
    //    commitment = Poseidon(irisHash, secretKey)
    // =====================
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== saltHasher.out;
    commitmentHasher.inputs[1] <== secretKey;

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
    // 4. Hamming distance check on iris codes (also booleanity of both codes)
    // =====================
    component hamming = HammingDistance(codeSize, hammingThreshold);
    for (var i = 0; i < codeSize; i++) {
        hamming.a[i] <== irisCodeLive[i];
        hamming.b[i] <== irisCodeRegistered[i];
    }

    valid <== hamming.pass;
    valid === 1;

    // =====================
    // 5. Sensor attestation over the live code
    // =====================
    component liveHash = PackedBitsHash(codeSize);
    for (var i = 0; i < codeSize; i++) {
        liveHash.bits[i] <== irisCodeLive[i];
    }

    component attest = SensorAttestation(sensorLevels);
    attest.liveHash <== liveHash.out;
    attest.electionId <== electionId;
    attest.nullifier <== nullifier;
    attest.sensorRoot <== sensorRoot;
    attest.sessionNonce <== sessionNonce;
    attest.sensorAx <== sensorAx;
    attest.sensorAy <== sensorAy;
    attest.sigR8x <== sigR8x;
    attest.sigR8y <== sigR8y;
    attest.sigS <== sigS;
    for (var i = 0; i < sensorLevels; i++) {
        attest.sensorPathElements[i] <== sensorPathElements[i];
        attest.sensorPathIndices[i] <== sensorPathIndices[i];
    }

    // =====================
    // 6. Bind voteBinding into the proof. A public input that appears in no
    //    constraint is not bound by Groth16, so square it into a dummy signal.
    // =====================
    signal voteBindingSq <== voteBinding * voteBinding;
}

// Instantiate with 256-bit downsampled iris codes, 20-level Merkle tree (~1M voters)
// Hamming threshold 0.478 → floor(0.478 × 256) + 1 = 123 (strict less-than)
component main {public [merkleRoot, nullifier, electionId, voteBinding, sensorRoot]} = IrisAuth(256, 20, 123, 10);
