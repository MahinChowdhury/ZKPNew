#!/bin/bash
# ============================================================
# measure_subcircuits.sh — R1CS constraint count per sub-circuit
#
# Compiles each template of face_auth / iris_auth in isolation
# (same flags as the production build: --O2) plus both full
# circuits, and writes results/subcircuit_constraints.json for
# the paper's constraint table. Under --O2 the optimiser works
# across template boundaries, so sub-circuit counts need not
# sum exactly to the full-circuit totals.
#
# Run from api-server/:  bash circuits/measure_subcircuits.sh
# ============================================================

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
CIRCOM="$(command -v circom || echo "$HERE/circom/target/release/circom")"
SNARKJS="node $HERE/../node_modules/snarkjs/cli.js"
WORK="$(mktemp -d)"
OUT="$HERE/../results"
mkdir -p "$OUT"

# name | include | instantiation
SUBS=(
  "PoseidonHashChunked(64,8)|common.circom|PoseidonHashChunked(64, 8)"
  "SquaredCosineSimilarity(64)|face_lib.circom|SquaredCosineSimilarity(64, 1225, 10000, 19)"
  "MerkleTreeChecker(20)|common.circom|MerkleTreeChecker(20)"
  "SensorAttestation(10)|common.circom|SensorAttestation(10)"
  "Poseidon(2)|node_modules/circomlib/circuits/poseidon.circom|Poseidon(2)"
  "PackedBitsHash(256)|iris_lib.circom|PackedBitsHash(256)"
  "HammingDistance(256)|iris_lib.circom|HammingDistance(256, 123)"
  # Metric baselines for the paper's comparison (sound, range-checked)
  "SquaredCosineSimilarity(128)|face_lib.circom|SquaredCosineSimilarity(128, 1225, 10000, 19)"
  "SquaredEuclideanDistance(64)|baselines/euclidean.circom|SquaredEuclideanDistance(64, 325000000000, 19)"
  "SquaredEuclideanDistance(128)|baselines/euclidean.circom|SquaredEuclideanDistance(128, 325000000000, 19)"
  "PoseidonHashChunked(128,8)|common.circom|PoseidonHashChunked(128, 8)"
)
# Output-dimension sweep (Fig. encoding_pareto, face_model_sweep.py): hash + comparator per d
for d in 16 32 48 80 96 112 160 192 256; do
  SUBS+=("PoseidonHashChunked($d,8)|common.circom|PoseidonHashChunked($d, 8)")
  SUBS+=("SquaredCosineSimilarity($d)|face_lib.circom|SquaredCosineSimilarity($d, 1225, 10000, 19)")
done

# Library copies of the main files without their `component main`
sed '/^component main/d' "$HERE/face_auth.circom" > "$HERE/face_lib.circom"
sed '/^component main/d' "$HERE/iris_auth.circom" > "$HERE/iris_lib.circom"
trap 'rm -f "$HERE/face_lib.circom" "$HERE/iris_lib.circom"; rm -rf "$WORK"' EXIT

count() {  # r1cs file -> number of constraints
  $SNARKJS r1cs info "$1" 2>/dev/null | sed -n 's/.*# of Constraints: \([0-9]*\).*/\1/p'
}

echo "{" > "$OUT/subcircuit_constraints.json"
first=1
for entry in "${SUBS[@]}"; do
  IFS='|' read -r name inc inst <<< "$entry"
  f="$WORK/sub.circom"
  printf 'pragma circom 2.1.6;\ninclude "%s/%s";\ncomponent main = %s;\n' "$HERE" "$inc" "$inst" > "$f"
  "$CIRCOM" "$f" --O2 --r1cs -o "$WORK" -l "$HERE/node_modules" -l "$HERE" > /dev/null
  n=$(count "$WORK/sub.r1cs")
  printf '  %s"%s": %s' "$([ $first = 1 ] || echo ',')" "$name" "$n" >> "$OUT/subcircuit_constraints.json"
  echo >> "$OUT/subcircuit_constraints.json"; first=0
  printf '%-32s %8s\n' "$name" "$n"
done
for c in face_auth iris_auth; do
  "$CIRCOM" "$HERE/$c.circom" --O2 --r1cs -o "$WORK" -l "$HERE/node_modules" > /dev/null
  n=$(count "$WORK/$c.r1cs")
  printf '  ,"%s (full)": %s\n' "$c" "$n" >> "$OUT/subcircuit_constraints.json"
  printf '%-32s %8s\n' "$c (full)" "$n"
done
# Embedding dimension of the compiled face circuit (base for the dimension sweep)
dim=$(sed -n 's/^component main.*FaceAuth(\([0-9]*\),.*/\1/p' "$HERE/face_auth.circom")
printf '  ,"face_auth (dim)": %s\n' "$dim" >> "$OUT/subcircuit_constraints.json"
echo "}" >> "$OUT/subcircuit_constraints.json"
echo "→ $OUT/subcircuit_constraints.json"
