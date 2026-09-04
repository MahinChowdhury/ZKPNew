#!/bin/bash
# ============================================================
# build_circuit.sh — Compile Circom circuit + PLONK setup
# Run from: api-server/circuits/
# Prerequisites: circom (v2.1.6+), snarkjs, node_modules/circomlib
# ============================================================

set -e

CIRCUIT=face_auth
PTAU_SIZE=18   # 2^18 = 262144 constraints (Merkle tree depth=20 adds ~20 Poseidon hashes)
PTAU_FILE="powersOfTau28_hez_final_${PTAU_SIZE}.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"

echo "============================================"
echo "  ZK-SNARK Circuit Build (Groth16)"
echo "============================================"

# ------------------------------------------
# Step 0: Ensure circomlib is installed
# ------------------------------------------
if [ ! -d "node_modules/circomlib" ]; then
    echo "[0/5] Installing circomlib..."
    npm init -y 2>/dev/null || true
    npm install circomlib
else
    echo "[0/5] circomlib already installed ✓"
fi

# ------------------------------------------
# Step 1: Compile Circom circuit
# ------------------------------------------
echo ""
echo "[1/5] Compiling ${CIRCUIT}.circom..."
circom ${CIRCUIT}.circom \
    --r1cs \
    --wasm \
    --sym \
    --c \
    --output . \
    -l node_modules

echo "  ✓ R1CS:  ${CIRCUIT}.r1cs"
echo "  ✓ WASM:  ${CIRCUIT}_js/${CIRCUIT}.wasm"
echo "  ✓ C++:   ${CIRCUIT}_cpp/"
echo "  ✓ SYM:   ${CIRCUIT}.sym"

echo ""
echo "[1.5/5] Compiling C++ witness generator..."
cd ${CIRCUIT}_cpp
make -j$(nproc)
cd ..
echo "  ✓ C++ witness binary: ${CIRCUIT}_cpp/${CIRCUIT}"

# Print circuit info
echo ""
echo "  Circuit info:"
npx snarkjs r1cs info ${CIRCUIT}.r1cs

# ------------------------------------------
# Step 2: Download Powers of Tau (if needed)
# ------------------------------------------
echo ""
if [ ! -f "${PTAU_FILE}" ]; then
    echo "[2/5] Downloading Powers of Tau (2^${PTAU_SIZE})..."
    curl -L -o ${PTAU_FILE} ${PTAU_URL}
else
    echo "[2/5] Powers of Tau already downloaded ✓"
fi

# ------------------------------------------
# Step 3: Groth16 Setup (phase 2 contribution included)
# ------------------------------------------
echo ""
echo "[3/5] Running Groth16 setup..."
npx snarkjs groth16 setup \
    ${CIRCUIT}.r1cs \
    ${PTAU_FILE} \
    ${CIRCUIT}_0000.zkey

npx snarkjs zkey contribute \
    ${CIRCUIT}_0000.zkey \
    ${CIRCUIT}.zkey \
    --name="Development Phase 2" -v -e="some random text for entropy"

rm ${CIRCUIT}_0000.zkey

echo "  ✓ Proving key: ${CIRCUIT}.zkey"

# ------------------------------------------
# Step 4: Export verification key
# ------------------------------------------
echo ""
echo "[4/5] Exporting verification key..."
npx snarkjs zkey export verificationkey \
    ${CIRCUIT}.zkey \
    verification_key.json

echo "  ✓ Verification key: verification_key.json"

# ------------------------------------------
# Step 5: Generate Solidity verifier (optional, for on-chain)
# ------------------------------------------
echo ""
echo "[5/5] Generating Solidity verifier (optional)..."
npx snarkjs zkey export solidityverifier \
    ${CIRCUIT}.zkey \
    PlonkVerifier.sol 2>/dev/null || echo "  (skipped — not needed for off-chain)"

echo ""
echo "============================================"
echo "  Build complete!"
echo ""
echo "  Files produced:"
echo "    ${CIRCUIT}.r1cs         — constraint system"
echo "    ${CIRCUIT}_js/          — WASM witness generator"
echo "    ${CIRCUIT}.zkey         — Groth16 proving key"
echo "    verification_key.json   — verification key"
echo "============================================"
