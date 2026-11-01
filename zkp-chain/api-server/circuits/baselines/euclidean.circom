// ============================================================
// euclidean.circom — sound squared-Euclidean comparator baseline
//
// For the paper's metric comparison only (not used by the voting
// circuits). Same soundness requirements as SquaredCosineSimilarity:
// every coordinate is range-checked to |x| < 2^coordBits so the sum
// cannot wrap modulo p, and the threshold is a template constant.
//
// For L2-normalised inputs scaled by s, ||a - b||^2 = s^2 (2 - 2 cos),
// so cos >= 0.35 corresponds to ||a - b||^2 <= 1.3 s^2 = 3.25 * 10^11 at s = 5e5.
// ============================================================

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template SignedRangeCheckE(bits) {
    signal input in;
    component n2b = Num2Bits(bits + 1);
    n2b.in <== in + (1 << bits);
}

template SquaredEuclideanDistance(n, threshold, coordBits) {
    signal input a[n];
    signal input b[n];
    signal output pass;

    component rangeA[n];
    component rangeB[n];
    signal diff[n];
    signal sq[n];
    signal acc[n + 1];
    acc[0] <== 0;
    for (var i = 0; i < n; i++) {
        rangeA[i] = SignedRangeCheckE(coordBits);
        rangeA[i].in <== a[i];
        rangeB[i] = SignedRangeCheckE(coordBits);
        rangeB[i].in <== b[i];
        diff[i] <== a[i] - b[i];
        sq[i] <== diff[i] * diff[i];
        acc[i + 1] <== acc[i] + sq[i];
    }

    // acc < n * 2^(2*coordBits + 2) <= 2^(2*coordBits + 9) for n <= 128
    component le = LessEqThan(2 * coordBits + 9);
    le.in[0] <== acc[n];
    le.in[1] <== threshold;
    pass <== le.out;
}
