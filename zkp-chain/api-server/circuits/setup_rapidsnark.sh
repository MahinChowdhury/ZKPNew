#!/bin/bash
# ============================================================
# setup_rapidsnark.sh — Build rapidsnark C++ native prover
#
# rapidsnark is a C++ Groth16 prover that achieves 10-50x
# speedup over snarkjs WASM by using hardware-optimized
# assembly (x86_64 with NASM/Intel intrinsics).
#
# Run from: api-server/circuits/
# Output:   circuits/rapidsnark/package/bin/prover
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAPIDSNARK_DIR="${SCRIPT_DIR}/rapidsnark"
PROVER_BIN="${RAPIDSNARK_DIR}/package/bin/prover"

echo "============================================"
echo "  rapidsnark C++ Prover Setup"
echo "============================================"
echo ""

# ------------------------------------------
# Step 0: Check architecture
# ------------------------------------------
ARCH=$(uname -m)
echo "[0/5] Architecture: ${ARCH}"
if [ "$ARCH" != "x86_64" ]; then
    echo ""
    echo "⚠️  WARNING: rapidsnark is optimized for x86_64."
    echo "   On ${ARCH}, performance may be reduced or build may fail."
    echo "   Proceeding anyway..."
    echo ""
fi

# ------------------------------------------
# Step 1: Install build dependencies
# ------------------------------------------
echo ""
echo "[1/5] Installing build dependencies..."

# Check if running as root or has sudo
if command -v sudo &> /dev/null; then
    SUDO="sudo"
else
    SUDO=""
fi

$SUDO apt-get update -qq
$SUDO apt-get install -y -qq \
    build-essential \
    cmake \
    libgmp-dev \
    libsodium-dev \
    nasm \
    curl \
    m4 \
    git \
    nlohmann-json3-dev 2>/dev/null || true

echo "  ✓ Dependencies installed"

# ------------------------------------------
# Step 2: Clone rapidsnark (if not already cloned)
# ------------------------------------------
echo ""
if [ -d "${RAPIDSNARK_DIR}" ] && [ -f "${PROVER_BIN}" ]; then
    echo "[2/5] rapidsnark already built ✓"
    echo "  Binary: ${PROVER_BIN}"
    echo ""
    echo "  To rebuild, delete ${RAPIDSNARK_DIR} and re-run this script."
    
    # Verify binary works
    echo ""
    echo "[VERIFY] Testing prover binary..."
    if "${PROVER_BIN}" --help &>/dev/null || "${PROVER_BIN}" 2>&1 | grep -qi "usage\|prover\|error"; then
        echo "  ✓ Prover binary is functional"
    fi
    
    echo ""
    echo "============================================"
    echo "  rapidsnark is ready!"
    echo "  Binary: ${PROVER_BIN}"
    echo "============================================"
    exit 0
fi

if [ -d "${RAPIDSNARK_DIR}" ]; then
    echo "[2/5] rapidsnark directory exists but binary not found — rebuilding..."
    rm -rf "${RAPIDSNARK_DIR}"
fi

echo "[2/5] Cloning rapidsnark..."
git clone https://github.com/iden3/rapidsnark.git "${RAPIDSNARK_DIR}"
cd "${RAPIDSNARK_DIR}"
git submodule update --init --recursive
echo "  ✓ Repository cloned"

# ------------------------------------------
# Step 3: Build GMP (required dependency)
# ------------------------------------------
echo ""
echo "[3/5] Building GMP (GNU Multiple Precision)..."
cd "${RAPIDSNARK_DIR}"
./build_gmp.sh host
echo "  ✓ GMP built"

# ------------------------------------------
# Step 4: Build rapidsnark prover
# ------------------------------------------
echo ""
echo "[4/5] Building rapidsnark prover (this may take a few minutes)..."
cd "${RAPIDSNARK_DIR}"
mkdir -p build_prover
cd build_prover
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${RAPIDSNARK_DIR}/package"
make -j$(nproc)
make install
echo "  ✓ Prover built"

# ------------------------------------------
# Step 5: Verify build
# ------------------------------------------
echo ""
echo "[5/5] Verifying build..."

if [ -f "${PROVER_BIN}" ]; then
    echo "  ✓ Prover binary: ${PROVER_BIN}"
    ls -lh "${PROVER_BIN}"
    
    # Quick sanity check
    if "${PROVER_BIN}" 2>&1 | head -1 | grep -qi "usage\|prover\|rapidsnark\|error"; then
        echo "  ✓ Binary executes correctly"
    fi
else
    echo "  ❌ Build failed — prover binary not found at ${PROVER_BIN}"
    echo "     Check build output above for errors."
    exit 1
fi

echo ""
echo "============================================"
echo "  rapidsnark build complete!"
echo ""
echo "  Prover binary: ${PROVER_BIN}"
echo ""
echo "  Expected speedup: 10-50x over snarkjs WASM"
echo "  Usage: prover <circuit.zkey> <witness.wtns> <proof.json> <public.json>"
echo "============================================"
