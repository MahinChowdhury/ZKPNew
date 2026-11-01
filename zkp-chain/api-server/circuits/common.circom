// ============================================================
// common.circom — templates shared by face_auth and iris_auth
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/switcher.circom";
include "node_modules/circomlib/circuits/eddsaposeidon.circom";

// ============================================================
// PoseidonHashChunked
// Hash an n-element array via Poseidon in chunkSize-element
// chunks, then hash the intermediate digests into one value.
// circomlib's Poseidon takes at most 16 inputs, so above 16
// chunks the digests are first hashed in g equal groups
// (n <= 128 at chunkSize 8 is unchanged: g = 1).
// ============================================================
template PoseidonHashChunked(n, chunkSize) {
    signal input in[n];
    signal output out;

    var numChunks = n \ chunkSize;  // n must be divisible by chunkSize
    var g = (numChunks + 15) \ 16;
    var groupSize = numChunks \ g;
    assert(numChunks == g * groupSize);

    component chunkHashers[numChunks];
    for (var i = 0; i < numChunks; i++) {
        chunkHashers[i] = Poseidon(chunkSize);
        for (var j = 0; j < chunkSize; j++) {
            chunkHashers[i].inputs[j] <== in[i * chunkSize + j];
        }
    }

    component finalHash = Poseidon(g == 1 ? numChunks : g);
    if (g == 1) {
        for (var i = 0; i < numChunks; i++) {
            finalHash.inputs[i] <== chunkHashers[i].out;
        }
    } else {
        component groupHashers[g];
        for (var k = 0; k < g; k++) {
            groupHashers[k] = Poseidon(groupSize);
            for (var j = 0; j < groupSize; j++) {
                groupHashers[k].inputs[j] <== chunkHashers[k * groupSize + j].out;
            }
            finalHash.inputs[k] <== groupHashers[k].out;
        }
    }

    out <== finalHash.out;
}

// ============================================================
// MerkleTreeChecker
// Verifies that a leaf is a member of a Poseidon binary Merkle
// tree with the given root.
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
        // circomlib's Switcher does not constrain sel; a non-boolean index
        // lets a prover solve the top level for any leaf (membership forgery).
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== levelHashes[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root === levelHashes[levels];
}

// ============================================================
// SensorAttestation
// Proves the live biometric sample was produced by an authorised
// capture device for THIS vote:
//   1. sessionCommit = Poseidon(nullifier, sessionNonce)
//   2. msg = Poseidon(liveHash, electionId, sessionCommit)
//   3. EdDSA-Poseidon(sensorKey) verifies on msg
//   4. Poseidon(sensorKey) is a leaf of the sensor registry (sensorRoot)
//
// sessionCommit hides the nullifier from the sensor, so the device that
// saw the voter's face cannot link it to the ballot; binding to the
// nullifier makes each attestation usable for exactly one vote, and
// binding to electionId stops replay across elections. Only the registry
// root is public, so the proof does not reveal which device was used.
// ============================================================
template SensorAttestation(sensorLevels) {
    signal input liveHash;
    signal input electionId;
    signal input nullifier;
    signal input sensorRoot;

    signal input sessionNonce;
    signal input sensorAx;
    signal input sensorAy;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input sensorPathElements[sensorLevels];
    signal input sensorPathIndices[sensorLevels];

    component sessionCommit = Poseidon(2);
    sessionCommit.inputs[0] <== nullifier;
    sessionCommit.inputs[1] <== sessionNonce;

    component msg = Poseidon(3);
    msg.inputs[0] <== liveHash;
    msg.inputs[1] <== electionId;
    msg.inputs[2] <== sessionCommit.out;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== sensorAx;
    sig.Ay <== sensorAy;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.S <== sigS;
    sig.M <== msg.out;

    component sensorLeaf = Poseidon(2);
    sensorLeaf.inputs[0] <== sensorAx;
    sensorLeaf.inputs[1] <== sensorAy;

    component registry = MerkleTreeChecker(sensorLevels);
    registry.leaf <== sensorLeaf.out;
    registry.root <== sensorRoot;
    for (var i = 0; i < sensorLevels; i++) {
        registry.pathElements[i] <== sensorPathElements[i];
        registry.pathIndices[i] <== sensorPathIndices[i];
    }
}
