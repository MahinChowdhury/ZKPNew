# ZKPNew – Zero-Knowledge Identity on Hyperledger Fabric

A Hyperledger Fabric network with Node.js chaincode implementing zero-knowledge proof based identity management.

## Prerequisites

- Docker & Docker Compose
- Node.js ≥ 16
- npm
- Git
- Hyperledger Fabric samples repository (will be used as base)

## Full Setup (Copy-Paste All Commands)

```bash
# 1. Run the project installer
./install.sh

# 2. Move zkp-chain folder into fabric-samples
mv zkp-chain fabric-samples/

# 3. Install dependencies
cd fabric-samples/zkp-chain/api-server
npm install

cd ../chaincode/identity
npm install

# 4. Enroll Admin & User for the API server
cd ../../zkp-chain/api-server
rm -rf wallet
node enrollAdmin.js
node enrollUser.js

# 5. Start Fabric test network with channel
cd ../../test-network
./network.sh up createChannel -ca -c mychannel

# 6. Add Fabric binaries to PATH and set config path
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config/

# 7. Package the chaincode
peer lifecycle chaincode package identity.tar.gz \
    --path ../zkp-chain/chaincode/identity \
    --lang node \
    --label identity_1.0

# 8. Install on Org1
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

peer lifecycle chaincode install identity.tar.gz

# 9. Install on Org2
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer lifecycle chaincode install identity.tar.gz

# 10. Get the package ID (you will see it in the output of the next command)
peer lifecycle chaincode queryinstalled

# Replace the hash below with your actual package ID from the previous command
export CC_PACKAGE_ID=identity_1.0:YOUR_PACKAGE_ID_HERE

# 11. Approve for Org2
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer lifecycle chaincode approveformyorg -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel --name identity --version 1.0 \
    --package-id $CC_PACKAGE_ID --sequence 1 --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

# 12. Approve for Org1
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

peer lifecycle chaincode approveformyorg -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel --name identity --version 1.0 \
    --package-id $CC_PACKAGE_ID --sequence 1 --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

# 13. Check commit readiness
peer lifecycle chaincode checkcommitreadiness --channelID mychannel \
    --name identity --version 1.0 --sequence 1 --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --output json

# 14. Commit chaincode definition
peer lifecycle chaincode commit -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel --name identity --version 1.0 --sequence 1 --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

# 15. Verify commitment
peer lifecycle chaincode querycommitted --channelID mychannel --name identity

# 16. Initialize ledger
peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    -C mychannel -n identity \
    --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    -c '{"function":"initLedger","Args":[]}'

# 17. Test query
peer chaincode query -C mychannel -n identity -c '{"function":"getRegisteredCount","Args":[]}'

```

## Start the API SERVER

```
cd fabric-samples/zkp-chain/api-server
npm start
```

## Packages for python-server

### * First you neeed to use venv of Python 3.10

```
pip install fastapi
pip install uvicorn
pip install python-multipart
pip install opencv-python
pip install mediapipe
pip install deepface
pip install numpy
pip install scikit-learn
```


