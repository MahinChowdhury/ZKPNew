// ============================================================
// face_common.circom — face-template templates shared by face_auth
// (voting) and enroll_auth (attested enrollment)
// ============================================================

pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";

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
// PackedCoordHash
// Hashes n coordinates that the caller range-checks to |x| < 2^coordBits
// (SquaredCosineSimilarity does, for both templates). Each offset value
// x + 2^coordBits fits in w = coordBits + 1 bits, so k = floor(253 / w)
// of them pack injectively into one field element by a linear
// combination, which costs no constraints; only the m = ceil(n / k)
// packed elements are hashed (128-D, coordBits = 19: 11 elements).
// Without the range checks, carries between slots alias distinct
// templates to one digest (attack A24).
// ============================================================
template PackedCoordHash(n, coordBits) {
    signal input in[n];
    signal output out;

    var w = coordBits + 1;
    var k = 253 \ w;
    var m = (n + k - 1) \ k;
    var g = (m + 15) \ 16;           // circomlib Poseidon takes at most 16 inputs
    assert(g <= 16);

    signal packed[m];
    for (var e = 0; e < m; e++) {
        var acc = 0;
        for (var j = 0; j < k; j++) {
            if (e * k + j < n) {
                acc += (in[e * k + j] + (1 << coordBits)) * (1 << (w * j));
            }
        }
        packed[e] <== acc;
    }

    if (g == 1) {
        component h = Poseidon(m);
        for (var e = 0; e < m; e++) { h.inputs[e] <== packed[e]; }
        out <== h.out;
    } else {
        component groupHashers[g];
        component finalHash = Poseidon(g);
        for (var q = 0; q < g; q++) {
            var size = (m - 16 * q) < 16 ? (m - 16 * q) : 16;
            groupHashers[q] = Poseidon(size);
            for (var j = 0; j < size; j++) { groupHashers[q].inputs[j] <== packed[16 * q + j]; }
            finalHash.inputs[q] <== groupHashers[q].out;
        }
        out <== finalHash.out;
    }
}
