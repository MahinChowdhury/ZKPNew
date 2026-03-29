// ============================================================
// face_auth.circom — ZK-SNARK for biometric voter authentication
// Stack: Circom 2 + PLONK, Poseidon hash, Baby Jubjub ECC
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// ============================================================
// PoseidonHashChunked
// Hash a 64-element array via Poseidon in 8-element chunks,
// then hash the 8 intermediate digests into one final hash.
// ============================================================
template PoseidonHashChunked(n, chunkSize) {
    signal input in[n];
    signal output out;

    // n must be divisible by chunkSize
    var numChunks = n \ chunkSize;  // integer division

    // Step 1: Hash each chunk of chunkSize elements
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
// SquaredCosineSimilarity
// Proves: (dot(a,b))^2 >= threshold_sq_num/threshold_sq_den * norm2(a) * norm2(b)
//
// Rearranged to avoid division:
//   dot_product^2 * threshold_sq_den >= threshold_sq_num * norm_a_sq * norm_b_sq
//
// All integer arithmetic — no sqrt, no division in constraints.
// ============================================================
template SquaredCosineSimilarity(n) {
    signal input a[n];
    signal input b[n];
    signal input threshold_sq_num;   // e.g. 25 for threshold 0.5 => 0.5^2 = 0.25 => 25/100
    signal input threshold_sq_den;   // e.g. 100

    signal output pass;              // 1 if similar, 0 otherwise

    // Compute dot product: sum(a[i] * b[i])
    signal dot_terms[n];
    signal dot_accum[n + 1];
    dot_accum[0] <== 0;
    for (var i = 0; i < n; i++) {
        dot_terms[i] <== a[i] * b[i];
        dot_accum[i + 1] <== dot_accum[i] + dot_terms[i];
    }
    signal dot_product <== dot_accum[n];

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

    // LHS = dot_product^2 * threshold_sq_den
    signal dot_sq <== dot_product * dot_product;
    signal lhs <== dot_sq * threshold_sq_den;

    // RHS = threshold_sq_num * norm_a_sq * norm_b_sq
    signal norms_product <== norm_a_sq * norm_b_sq;
    signal rhs <== threshold_sq_num * norms_product;

    // Compare: lhs >= rhs  =>  pass = 1
    // Use GreaterEqThan with enough bits to cover the range
    // With 64 dims, values scaled by 1e6, max value per dim ~ 1e6
    // dot_sq max ~ (64 * 1e12)^2 = ~4e27 => needs ~93 bits
    // We use 128 bits to be safe
    component gte = GreaterEqThan(128);
    gte.in[0] <== lhs;
    gte.in[1] <== rhs;

    pass <== gte.out;
}

// ============================================================
// FaceAuth — Main circuit
//
// Proves:
//   1. Poseidon(embedding || salt) == faceHash
//   2. S = k * G  on Baby Jubjub
//   3. squared_cosine(embedding, registeredEmbedding) >= threshold
// ============================================================
template FaceAuth(embeddingSize) {
    // --- Public Inputs ---
    signal input faceHash;               // Poseidon hash commitment
    signal input Sx;                     // Public key x on Baby Jubjub
    signal input Sy;                     // Public key y on Baby Jubjub
    signal input threshold_sq_num;       // Squared threshold numerator
    signal input threshold_sq_den;       // Squared threshold denominator

    // --- Private Inputs ---
    signal input embedding[embeddingSize];              // Live face (integer-scaled)
    signal input registeredEmbedding[embeddingSize];    // Registered face (integer-scaled)
    signal input k;                                     // Private scalar
    signal input salt;                                  // Salt for hash

    // --- Output ---
    signal output valid;

    // =====================
    // 1. Poseidon hash check: H(embedding || salt) == faceHash
    // =====================
    // Hash the embedding
    component embeddingHash = PoseidonHashChunked(embeddingSize, 8);
    for (var i = 0; i < embeddingSize; i++) {
        embeddingHash.in[i] <== registeredEmbedding[i];
    }

    // Combine embedding hash with salt
    component finalHash = Poseidon(2);
    finalHash.inputs[0] <== embeddingHash.out;
    finalHash.inputs[1] <== salt;

    // Constrain: computed hash must equal public faceHash
    finalHash.out === faceHash;

    // =====================
    // 2. Baby Jubjub key ownership: S = k * G
    // =====================
    component bjjMul = BabyPbk();
    bjjMul.in <== k;

    // Constrain: computed public key must match declared (Sx, Sy)
    bjjMul.Ax === Sx;
    bjjMul.Ay === Sy;

    // =====================
    // 3. Squared cosine similarity check
    // =====================
    component cosine = SquaredCosineSimilarity(embeddingSize);
    for (var i = 0; i < embeddingSize; i++) {
        cosine.a[i] <== embedding[i];
        cosine.b[i] <== registeredEmbedding[i];
    }
    cosine.threshold_sq_num <== threshold_sq_num;
    cosine.threshold_sq_den <== threshold_sq_den;

    // All three checks must pass
    // (faceHash and key ownership are hard constraints via ===)
    // Cosine similarity must be strictly enforced:
    valid <== cosine.pass;
    valid === 1;
}

// Instantiate with 64-dimensional embeddings
component main {public [faceHash, Sx, Sy, threshold_sq_num, threshold_sq_den]} = FaceAuth(64);
