# ZKPNew – Zero-Knowledge Identity on Hyperledger Fabric

A Hyperledger Fabric network with Node.js chaincode implementing zero-knowledge proof based identity management.

## Prerequisites

- Docker & Docker Compose
- Node.js ≥ 16
- jq
- npm
- Git
- Hyperledger Fabric samples repository (will be used as base)

## File Structuring

```
./install.sh
mv fabric-samples/ ZKPNew/
mv zkp-chain fabric-samples/
```

## npm install
```
sudo apt remove nodejs npm -y
sudo apt purge nodejs npm -y
sudo apt autoremove -y

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install --lts
nvm use --lts
```

## Chaincode deployment

```
cd fabric-samples/zkp-chain/chaincode/identity
npm install

move the file chain-deployment.sh to : fabric-samples/zkp-chain/test-network

chmod +x ./chain-deployment.sh
./chain-deployment.sh

```

## Start the API SERVER

```
cd fabric-samples/zkp-chain/api-server
npm install
npm start
```

## Packages for python-server

### * First you neeed to use venv of Python 3.10

```
python3.10 -m venv venv
source venv/bin/activate

pip install fastapi uvicorn python-multipart scikit-learn
pip install deepface
pip install "tensorflow==2.15.0" "protobuf==3.20.3" "numpy<2.0.0" "ml-dtypes==0.2.0" "mediapipe==0.10.9"
pip uninstall opencv-python opencv-contrib-python -y
pip install "opencv-python-headless<4.10.0"
```

## Install circom circuits

```
sudo apt-get update
sudo apt-get install -y build-essential libgmp-dev nasm curl git

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
sudo cp target/release/circom /usr/local/bin/
cd ..


npm install -g snarkjs

# Compile Face Circuit
circom face_auth.circom --r1cs --wasm --sym
# Compile Iris Circuit
circom iris_auth.circom --r1cs --wasm --sym


chmod +x setup_rapidsnark.sh
./setup_rapidsnark.sh

chmod +x build_circuit.sh
./build_circuit.sh

chmod +x build_iris_circuit.sh
./build_iris_circuit.sh

```

