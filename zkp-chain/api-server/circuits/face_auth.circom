// ============================================================
// face_auth.circom — ZK-SNARK for biometric voter authentication
// Architecture: Merkle Tree + Nullifier (Semaphore-style)
//               + in-circuit sensor attestation of the live sample
// Stack: Circom 2 + Groth16, Poseidon hash, EdDSA-Poseidon (BabyJubJub)
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "common.circom";

// ============================================================
// SignedRangeCheck
// Constrains x to the integer range [-2^bits, 2^bits).
// ============================================================
template SignedRangeCheck(bits) {
    signal input in;
    component n2b = Num2Bits(bits + 1);
    n2b.in <== in + (1 << bits);
}

// ============================================================
// SquaredCosineSimilarity
// Proves: dot(a,b) >= 0  and
//         (dot(a,b))^2 >= thNum/thDen * norm2(a) * norm2(b)
// i.e. cos(a,b) >= sqrt(thNum/thDen).
//
// Rearranged to avoid division:
//   dot_product^2 * thDen >= thNum * norm_a_sq * norm_b_sq
//
// The threshold is a template parameter (fixed by the verification
// key), never a prover-chosen input. Every coordinate is range-checked
// to |x| < 2^coordBits so no intermediate wraps modulo p:
//   |dot|, norms  < n * 2^(2*coordBits)        <= 2^dotBits,  dotBits = 2*coordBits + log2(n)
//   lhs, rhs      < 2^(2*dotBits) * 2^14        = 2^cmpBits    (thNum <= thDen < 2^14)
// so a comparator of cmpBits is exact (128-D, coordBits = 19: 45 and 104 bits).
// ============================================================
template SquaredCosineSimilarity(n, thNum, thDen, coordBits) {
    var logN = 0;
    while ((1 << logN) < n) { logN++; }
    var dotBits = 2 * coordBits + logN;
    var cmpBits = 2 * dotBits + 14;
    assert(thNum <= thDen && thDen < (1 << 14));
    assert(cmpBits <= 252);

    signal input a[n];
    signal input b[n];

    signal output pass;              // 1 if similar, 0 otherwise

    component rangeA[n];
    component rangeB[n];
    for (var i = 0; i < n; i++) {
        rangeA[i] = SignedRangeCheck(coordBits);
        rangeA[i].in <== a[i];
        rangeB[i] = SignedRangeCheck(coordBits);
        rangeB[i].in <== b[i];
    }

    // Compute dot product: sum(a[i] * b[i])
    signal dot_terms[n];
    signal dot_accum[n + 1];
    dot_accum[0] <== 0;
    for (var i = 0; i < n; i++) {
        dot_terms[i] <== a[i] * b[i];
        dot_accum[i + 1] <== dot_accum[i] + dot_terms[i];
    }
    signal dot_product <== dot_accum[n];

    // Squaring loses the sign: without this, cos = -1 (a negated template) passes.
    // Given the range checks, dot is an integer in (-2^dotBits, 2^dotBits);
    // requiring it to fit in dotBits unsigned bits rejects every negative value.
    component dotNonNeg = Num2Bits(dotBits);
    dotNonNeg.in <== dot_product;

    // Compute ||a||^2 = sum(a[i]^2)
    signal norm_a_terms[n];
    signal norm_a_accum[n + 1];
    norm_a_accum[0] <== 0;
    for (var i = 0; i < n; i++) {
        norm_a_terms[i] <== a[i] * a[i];
        norm_a_accum[i + 1] <== norm_a_accum[i] + norm_a_terms[i];
    }
    signal norm_a_sq <== norm_a_accum[n];

    // Compute ||b||^2 = sum(b[i]^2)
    signal norm_b_terms[n];
    signal norm_b_accum[n + 1];
    norm_b_accum[0] <== 0;
    for (var i = 0; i < n; i++) {
        norm_b_terms[i] <== b[i] * b[i];
        norm_b_accum[i + 1] <== norm_b_accum[i] + norm_b_terms[i];
    }
    signal norm_b_sq <== norm_b_accum[n];

    // LHS = dot_product^2 * thDen
    signal dot_sq <== dot_product * dot_product;
    signal lhs <== dot_sq * thDen;

    // RHS = thNum * norm_a_sq * norm_b_sq
    signal norms_product <== norm_a_sq * norm_b_sq;
    signal rhs <== thNum * norms_product;

    // Compare: lhs >= rhs  =>  pass = 1 (both < 2^cmpBits by the range checks above)
    component gte = GreaterEqThan(cmpBits);
    gte.in[0] <== lhs;
    gte.in[1] <== rhs;

    pass <== gte.out;
}

// ============================================================
// FaceAuth — Main circuit (Merkle + Nullifier architecture)
//
// Proves:
//   1. faceHash = Poseidon(registeredEmbedding || salt)   (private)
//   2. commitment = Poseidon(faceHash, secretKey) is in the Merkle tree
//   3. nullifier = Poseidon(secretKey, electionId)
//   4. cos(liveEmbedding, registeredEmbedding) >= sqrt(thNum/thDen)
//   5. the live embedding was signed by an authorised capture device for
//      this vote (SensorAttestation) — without this the live sample is a
//      free witness and the proof only shows knowledge of the template
//   6. the proof is bound to voteBinding (hash of the ballot ciphertexts)
//
// faceHash is deliberately NOT public: it is constant per voter, so
// publishing it would link every ballot a voter casts across elections.
// ============================================================
template FaceAuth(embeddingSize, treeLevels, thNum, thDen, sensorLevels) {
    // --- Public Inputs ---
    signal input merkleRoot;             // Root of the voter commitment Merkle tree
    signal input nullifier;              // Nullifier = Poseidon(secretKey, electionId)
    signal input electionId;             // Unique election identifier
    signal input voteBinding;            // H(ballot ciphertexts), checked by the chaincode
    signal input sensorRoot;             // Root of the authorised-sensor registry

    // --- Private Inputs ---
    signal input embedding[embeddingSize];              // Live face (integer-scaled)
    signal input registeredEmbedding[embeddingSize];    // Registered face (integer-scaled)
    signal input salt;                                  // Salt for hash
    signal input secretKey;                             // Voter's secret key
    signal input pathElements[treeLevels];              // Merkle proof siblings
    signal input pathIndices[treeLevels];               // Merkle proof path (0=left, 1=right)

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
    // 1. faceHash = H(registeredEmbedding || salt)
    // =====================
    component embeddingHash = PoseidonHashChunked(embeddingSize, 8);
    for (var i = 0; i < embeddingSize; i++) {
        embeddingHash.in[i] <== registeredEmbedding[i];
    }

    component faceHasher = Poseidon(2);
    faceHasher.inputs[0] <== embeddingHash.out;
    faceHasher.inputs[1] <== salt;

    // =====================
    // 2. Compute commitment and verify Merkle membership
    //    commitment = Poseidon(faceHash, secretKey)
    // =====================
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== faceHasher.out;
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
    // 4. Squared cosine similarity check
    // =====================
    // Coordinates are unit-vector components scaled by 5e5 < 2^19
    component cosine = SquaredCosineSimilarity(embeddingSize, thNum, thDen, 19);
    for (var i = 0; i < embeddingSize; i++) {
        cosine.a[i] <== embedding[i];
        cosine.b[i] <== registeredEmbedding[i];
    }

    valid <== cosine.pass;
    valid === 1;

    // =====================
    // 5. Sensor attestation over the live embedding
    // =====================
    component liveHash = PoseidonHashChunked(embeddingSize, 8);
    for (var i = 0; i < embeddingSize; i++) {
        liveHash.in[i] <== embedding[i];
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

// 128-D PCA of InsightFace buffalo_l (model/app.py), 20-level voter tree (~1M voters),
// cos >= 0.35 (0.35^2 = 1225/10000), 10-level sensor registry (1,024 capture devices).
// d and tau chosen on validation identities only (model/select_operating_point_targeted.py):
// lowest tau with lookalike success <= 1% against an attacker screening 100 recruits,
// smallest d with FRR <= 1%.
component main {public [merkleRoot, nullifier, electionId, voteBinding, sensorRoot]} = FaceAuth(128, 20, 1225, 10000, 10);
