#!/bin/bash
# ============================================================
# build_circuit.sh — Compile Circom circuit + PLONK setup
# Run from: api-server/circuits/
# Prerequisites: circom (v2.1.6+), snarkjs, node_modules/circomlib
# ============================================================

set -e

CIRCUIT=enroll_auth
PTAU_SIZE=${PTAU_SIZE:-16}   # verified PSE ppot 2^16; covers face 32,668 (PCA-128, 2^15 domain) / iris 17,518
# PSE perpetual powers of tau (the Hermez mirrors return 403 as of 2026-10)
PTAU_FILE="ppot_0080_${PTAU_SIZE}.ptau"
PTAU_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/${PTAU_FILE}"

# Use circom from PATH, else the copy built in ./circom
CIRCOM="$(command -v circom || echo ./circom/target/release/circom)"

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
"$CIRCOM" ${CIRCUIT}.circom \
    --O2 --r1cs \
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
# Optional (snark.js falls back to WASM). Never leave a stale binary behind:
# it would compute witnesses for the previous circuit.
if (cd ${CIRCUIT}_cpp && make -j$(nproc) > /dev/null 2>&1); then
    echo "  ✓ C++ witness binary: ${CIRCUIT}_cpp/${CIRCUIT}"
else
    rm -f ${CIRCUIT}_cpp/${CIRCUIT}
    echo "  ⚠ C++ witness build skipped (needs libgmp-dev nlohmann-json3-dev nasm) — WASM witness will be used"
fi

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
    curl -fL -o ${PTAU_FILE} ${PTAU_URL}
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
    --name="Development Phase 2" -v -e="$(head -c 32 /dev/urandom | xxd -p -c 64)"

rm ${CIRCUIT}_0000.zkey

echo "  ✓ Proving key: ${CIRCUIT}.zkey"

# ------------------------------------------
# Step 4: Export verification key
# ------------------------------------------
echo ""
echo "[4/5] Exporting verification key..."
npx snarkjs zkey export verificationkey \
    ${CIRCUIT}.zkey \
    enroll_verification_key.json

cp enroll_verification_key.json ../../chaincode/identity/lib/enroll_verification_key.json
echo "  ✓ Verification key: enroll_verification_key.json (copied to chaincode/identity/lib/)"

echo "============================================"
echo "  Build complete!"
echo ""
echo "  Files produced:"
echo "    ${CIRCUIT}.r1cs         — constraint system"
echo "    ${CIRCUIT}_js/          — WASM witness generator"
echo "    ${CIRCUIT}.zkey         — Groth16 proving key"
echo "    enroll_verification_key.json   — verification key"
echo "============================================"
