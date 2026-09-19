# 🛡️ BBZKV: Biometric-Bound Zero-Knowledge Voting System

**Biometric-Bound Zero-Knowledge Voting (BBZKV)** is an end-to-end verifiable (E2EV), privacy-preserving decentralized e-voting system that binds voter eligibility directly to Face and Iris biometrics using **Groth16 ZK-SNARKs** on a **Hyperledger Fabric** permissioned blockchain.

---

## 📋 System Prerequisites

Ensure your system (Ubuntu 22.04 LTS or WSL 2 on Windows 11) has the following dependencies installed:

1. **Node.js & npm** (v20.x LTS or higher)
   ```bash
   node -v   # Output should be >= v20.0.0
   ```
2. **Docker & Docker Compose** (v2.x+)
   ```bash
   docker --version
   docker compose version
   ```
3. **Python 3 & Virtual Environment** (v3.10+)
   ```bash
   python3 --version
   sudo apt update && sudo apt install -y python3-venv python3-pip
   ```
4. **Circom 2** (v2.1.6+)
   ```bash
   # Install Rust if needed: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   git clone https://github.com/iden3/circom.git
   cd circom && cargo build --release
   cargo install --path circom
   circom --version
   ```
5. **SnarkJS**
   ```bash
   npm install -g snarkjs
   ```

---

## 🚀 Step-by-Step System Execution Guide

### Step 1: Clone Repository & Install Dependencies

```bash
git clone https://github.com/MahinChowdhury/ZKPNew.git
cd ZKPNew
```

#### Install API Server Dependencies
```bash
cd zkp-chain/api-server
npm install
cd ../..
```

#### Setup Python Biometric Model Environment
```bash
cd zkp-chain/model
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # FastAPI, uvicorn, torch, torchvision, opencv-python, pillow, scikit-learn
cd ../..
```

---

### Step 2: Build Zero-Knowledge Circuits & Setup Keys

Compile the Circom circuits, generate the local Powers of Tau transcript (`pot15_final.ptau`), and derive the Groth16 proving and verification keys:

```bash
cd zkp-chain/api-server/circuits

# Make build script executable and execute it
chmod +x build_circuit.sh
./build_circuit.sh
```

> **What `build_circuit.sh` does:**
> - Compiles `face_auth.circom` $\rightarrow$ `face_auth.r1cs` & `face_auth_js/face_auth.wasm`.
> - Generates `pot15_final.ptau` locally using `snarkjs powersoftau new bn128 15`.
> - Prepares Groth16 proving key (`face_auth.zkey`) & verification key (`verification_key.json`).

Copy the verification key to the Fabric chaincode directory:
```bash
cp verification_key.json ../../chaincode/identity/lib/verification_key.json
cd ../../..
```

---

### Step 3: Deploy Hyperledger Fabric Network & Chaincode

Start Docker and launch the Hyperledger Fabric permissioned network (Raft orderer, 2 peer orgs, `mychannel`, `identity` chaincode):

```bash
# Ensure Docker service is running
sudo service docker start   # (Required on WSL)

# Run the automated Fabric deployment script
chmod +x chain-deployment.sh
./chain-deployment.sh
```

---

### Step 4: Start System Services

You will need **two terminal windows** to run the complete system:

#### Terminal 1: Python Biometric Feature Extraction Server (Port 8000)
```bash
cd ZKPNew/zkp-chain/model
source venv/bin/activate
python3 app.py
```
*(Runs FastAPI server on `http://localhost:8000` for 128D FaceNet embedding extraction & 64D PCA integer quantization).*

#### Terminal 2: API Gateway & Proof Orchestrator (Port 3000)
```bash
cd ZKPNew/zkp-chain/api-server

# Enroll Fabric Gateway Administrator & User Identity
node enrollAdmin.js
node enrollUser.js

# Start API server
node server.js
```
*(Runs Express server & WebSocket gateway on `http://localhost:3000`).*

---

### Step 5: Test the System & Access UI

Open your browser and navigate to:
```
http://localhost:3000
```

#### Voter Lifecycle Workflow:
1. **Ballot Creation:** Define election title and candidate list.
2. **Voter Registration:** Upload voter facial image $\rightarrow$ extracts 64D PCA vector $\rightarrow$ computes Poseidon commitment $\rightarrow$ appends leaf to on-chain Sparse Merkle Tree (SMT).
3. **Vote Casting:** Upload live facial photo & choose candidate $\rightarrow$ generates Groth16 ZK proof ($\Pi$) $\rightarrow$ verifies Merkle path membership & election nullifier $\nu = \text{Poseidon}(sk, \text{electionId})$ $\rightarrow$ commits vote ciphertext to Fabric ledger.
4. **Homomorphic Tallying:** Decrypts ElGamal candidate ciphertexts using Baby-Step Giant-Step (BSGS) offline decryption.

---

## 🛠️ Project Directory Structure

```
ZKPNew/
├── chain-deployment.sh       # Automated Hyperledger Fabric network & chaincode deployment
├── install-fabric.sh         # Fabric binary download script
├── zkp-chain/
│   ├── api-server/           # Node.js API Gateway, Groth16 Prover & Merkle Tree Manager
│   │   ├── circuits/         # Circom zero-knowledge circuits (face_auth.circom, build_circuit.sh)
│   │   ├── crypto/           # snark.js wrapper, Poseidon hashing, ElGamal encryption
│   │   ├── server.js         # Main Express API server
│   │   ├── enrollAdmin.js    # Fabric identity enroller
│   │   └── enrollUser.js     # Fabric user registration
│   ├── chaincode/            # Hyperledger Fabric Node.js Smart Contract (identityContract.js)
│   │   └── identity/lib/     # Verification keys & on-chain Groth16 pairing verifier
│   ├── model/                # Python FaceNet feature extraction & PCA quantization (app.py)
│   ├── frontend/             # Responsive Web UI interface
│   └── IEEE_Transaction_Mahin/# LaTeX source code for IEEE Transactions paper (ieee-paper.tex)
└── .gitignore                # Git exclusion rules for node_modules, keys & build artifacts
```

---

## 🔬 Citation

If you use this codebase or paper in your research, please cite:

```bibtex
@article{chowdhury2026bbzkv,
  title={Composable Security for Biometric-Bound Zero-Knowledge Voting: A Decentralized Architecture with Face and Iris Case Studies},
  author={Chowdhury, Mahin R. and Hasan, K. M. Azharul and Das, Arpita},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2026}
}
```
