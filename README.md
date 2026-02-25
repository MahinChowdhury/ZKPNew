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

pip install fastapi
pip install uvicorn
pip install python-multipart
pip install opencv-python
pip install mediapipe
pip install deepface
pip install numpy
pip install scikit-learn
pip install tf-keras
```


