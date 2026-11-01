#!/bin/bash
# ============================================================
# build_test_artifacts.sh — compile the CURRENT circuit sources into an
# isolated build dir for the soundness attack suite.
# Run from anywhere:  bash attacks/soundness/build_test_artifacts.sh [face|iris|all]
#
# Uses a 2^16 ptau (the PCA-128 face circuit has 32,668 constraints, a 2^15 domain).
# These keys are for testing only; production keys come from circuits/build_*.sh.
# ============================================================

set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
CIRCUITS="$HERE/../../circuits"
BUILD="$HERE/build"
CIRCOM="$CIRCUITS/circom/target/release/circom"
SNARKJS="node $HERE/../../node_modules/snarkjs/cli.js"
PTAU_SIZE=16   # any size >= 2^15 works for the 32,668-constraint face circuit
PTAU="$BUILD/powersOfTau28_hez_final_${PTAU_SIZE}.ptau"

mkdir -p "$BUILD"

if [ ! -f "$PTAU" ]; then
    # The Hermez mirrors (storage.googleapis.com/zkevm, hermez.s3) return 403 as of 2026-10.
    echo "Downloading ptau 2^${PTAU_SIZE} (PSE perpetual powers of tau)..."
    if ! curl -sfL -o "$PTAU" "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_${PTAU_SIZE}.ptau"; then
        # Local ptau is acceptable here: these keys only exist to run the attack suite.
        echo "Download failed — generating a local test ptau"
        rm -f "$PTAU"
        $SNARKJS powersoftau new bn128 $PTAU_SIZE "$BUILD/pot_0000.ptau" > /dev/null
        $SNARKJS powersoftau contribute "$BUILD/pot_0000.ptau" "$BUILD/pot_0001.ptau" \
            --name="test" -e="$(head -c 32 /dev/urandom | xxd -p -c 64)" > /dev/null
        $SNARKJS powersoftau prepare phase2 "$BUILD/pot_0001.ptau" "$PTAU" > /dev/null
        rm "$BUILD/pot_0000.ptau" "$BUILD/pot_0001.ptau"
    fi
fi

build() {
    local name=$1
    echo "=== Building $name ==="
    "$CIRCOM" "$CIRCUITS/$name.circom" --O2 --r1cs --wasm --output "$BUILD" -l "$CIRCUITS/node_modules" > "$BUILD/${name}_compile.log"
    $SNARKJS r1cs info "$BUILD/$name.r1cs" | tee "$BUILD/${name}_r1cs_info.txt"
    $SNARKJS groth16 setup "$BUILD/$name.r1cs" "$PTAU" "$BUILD/${name}_0000.zkey" > /dev/null
    $SNARKJS zkey contribute "$BUILD/${name}_0000.zkey" "$BUILD/$name.zkey" \
        --name="soundness-test" -e="$(head -c 32 /dev/urandom | xxd -p -c 64)" > /dev/null
    rm "$BUILD/${name}_0000.zkey"
    $SNARKJS zkey export verificationkey "$BUILD/$name.zkey" "$BUILD/${name}_vkey.json" > /dev/null
    echo "  -> $BUILD/$name.zkey, ${name}_vkey.json"
}

case "${1:-all}" in
    face) build face_auth ;;
    iris) build iris_auth ;;
    all)  build face_auth; build iris_auth ;;
    *)    echo "usage: $0 [face|iris|all]"; exit 1 ;;
esac
