#!/bin/bash
# ============================================================
# bench_dim.sh — face circuit at the deployed 128-D vs raw 512-D ArcFace:
# constraints, proving key, WASM proving time, peak memory of the prover.
#   bash benchmark/bench_dim.sh [runs]     (from api-server/; ~10 min)
# Output: results/dim_cost.json
# Keys are for measurement only (single local contribution).
# ============================================================
set -e
cd "$(dirname "$0")/.."
RUNS=${1:-10}
CIRCOM=circuits/circom/target/release/circom
SNARKJS="node node_modules/snarkjs/cli.js"
PTAU=circuits/ppot_0080_16.ptau
OUT=results/dim_cost.json

: > "$OUT.tmp"
for D in 128 512; do
    DIR=benchmark/build_dim/d$D
    mkdir -p "$DIR"
    if [ ! -f "$DIR/face_auth.zkey" ]; then
        echo "=== d=$D: compile + setup ==="
        sed "s/= FaceAuth(128, 20, 1225, 10000, 10);/= FaceAuth($D, 20, 1225, 10000, 10);/" circuits/face_auth.circom > "$DIR/face_auth.circom"
        $CIRCOM "$DIR/face_auth.circom" --O2 --r1cs --wasm --output "$DIR" -l circuits > "$DIR/compile.log"
        $SNARKJS groth16 setup "$DIR/face_auth.r1cs" "$PTAU" "$DIR/f0.zkey" > /dev/null
        $SNARKJS zkey contribute "$DIR/f0.zkey" "$DIR/face_auth.zkey" --name=bench -e="$(head -c 32 /dev/urandom | xxd -p -c 64)" > /dev/null
        rm "$DIR/f0.zkey"
        $SNARKJS zkey export verificationkey "$DIR/face_auth.zkey" "$DIR/vkey.json" > /dev/null
    fi
    echo "=== d=$D: $RUNS proofs ==="
    node benchmark/bench_dim.js "$D" "$RUNS" | tee -a "$OUT.tmp"
done
python3 -c "import json,sys; rows=[json.loads(l) for l in open('$OUT.tmp')]; json.dump({'date': __import__('datetime').datetime.utcnow().isoformat()+'Z', 'prover': 'snarkjs WASM (Node)', 'results': rows}, open('$OUT','w'), indent=1)"
rm "$OUT.tmp"
echo "wrote $OUT"
