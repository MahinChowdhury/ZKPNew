// ============================================================
// enroll_auth.circom — attested enrollment (FINDINGS C26)
//
// Without it the RA cannot tell whether the commitment a client submits
// encodes the enrollee's own face: B could enroll a commitment to A's
// template under B's NID and let A vote as B (attack A25). Here the
// supervised enrollment kiosk signs the packed digest of the template it
// captured, bound to the NID the RA operator entered, and the client
// proves that its commitment opens to exactly that template:
//   1. every coordinate is range-checked (|x| < 2^19), so the packed
//      digest binds the template (see PackedCoordHash)
//   2. commitment = Poseidon(Poseidon(digest, salt), secretKey)
//   3. a registered device signed Poseidon(digest, ENROLL_DOMAIN,
//      Poseidon(nidField, 0)) — SensorAttestation with the election slot
//      fixed to a domain constant no electionId (< 2^128) can take, so
//      enrollment and vote attestations are not interchangeable
// Public: commitment, nidField = trunc248(SHA256(nidHash)), sensorRoot.
// The template, salt and secret key stay private, as at voting time.
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "common.circom";
include "face_common.circom";

template EnrollAuth(embeddingSize, sensorLevels) {
    var COORD_BITS = 19;
    var ENROLL_DOMAIN = 1 << 200;

    // --- Public Inputs ---
    signal input commitment;
    signal input nidField;
    signal input sensorRoot;

    // --- Private Inputs ---
    signal input enrolled[embeddingSize];
    signal input salt;
    signal input secretKey;
    signal input sensorAx;
    signal input sensorAy;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input sensorPathElements[sensorLevels];
    signal input sensorPathIndices[sensorLevels];

    // 1. Range checks: make the packing below injective
    component range[embeddingSize];
    for (var i = 0; i < embeddingSize; i++) {
        range[i] = SignedRangeCheck(COORD_BITS);
        range[i].in <== enrolled[i];
    }

    component digest = PackedCoordHash(embeddingSize, COORD_BITS);
    for (var i = 0; i < embeddingSize; i++) {
        digest.in[i] <== enrolled[i];
    }

    // 2. The submitted commitment opens to this template
    component faceHasher = Poseidon(2);
    faceHasher.inputs[0] <== digest.out;
    faceHasher.inputs[1] <== salt;

    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== faceHasher.out;
    commitmentHasher.inputs[1] <== secretKey;
    commitmentHasher.out === commitment;

    // 3. A registered kiosk captured this template for this NID
    component attest = SensorAttestation(sensorLevels);
    attest.liveHash <== digest.out;
    attest.electionId <== ENROLL_DOMAIN;
    attest.nullifier <== nidField;
    attest.sessionNonce <== 0;
    attest.sensorRoot <== sensorRoot;
    attest.sensorAx <== sensorAx;
    attest.sensorAy <== sensorAy;
    attest.sigR8x <== sigR8x;
    attest.sigR8y <== sigR8y;
    attest.sigS <== sigS;
    for (var i = 0; i < sensorLevels; i++) {
        attest.sensorPathElements[i] <== sensorPathElements[i];
        attest.sensorPathIndices[i] <== sensorPathIndices[i];
    }
}

// 128-D face template, 10-level device registry (same as face_auth)
component main {public [commitment, nidField, sensorRoot]} = EnrollAuth(128, 10);
