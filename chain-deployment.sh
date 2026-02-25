#!/bin/bash

# ============================================
# Chaincode Deployment Script for Hyperledger Fabric
# ============================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_NETWORK_PATH="$HOME/mahin/ZKPNew/fabric-samples/test-network"
CHAINCODE_PATH="$HOME/mahin/ZKPNew/fabric-samples/zkp-chain/chaincode/identity"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Chaincode Deployment${NC}"
echo -e "${BLUE}============================================${NC}\n"

# ============================================
# STEP 1: CLEAN UP EXISTING DEPLOYMENT
# ============================================

echo -e "${YELLOW}Step 1: Cleaning up existing deployment...${NC}"

cd "$TEST_NETWORK_PATH"

./network.sh down

docker rm -f $(docker ps -aq) 2>/dev/null || true
docker volume prune -f

rm -f identity.tar.gz

echo -e "${GREEN}✅ Cleanup complete${NC}\n"

# ============================================
# STEP 2: START FABRIC NETWORK
# ============================================

echo -e "${YELLOW}Step 2: Starting Hyperledger Fabric network...${NC}"

./network.sh up createChannel -ca -c mychannel

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to start network${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Network started successfully${NC}\n"

echo -e "${YELLOW}Waiting for network to stabilize...${NC}"
sleep 5

# ============================================
# STEP 3: PREPARE CHAINCODE
# ============================================

echo -e "${YELLOW}Step 3: Preparing chaincode...${NC}"

cd "$CHAINCODE_PATH"

sudo rm -rf node_modules package-lock.json
npm install

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ npm install failed${NC}"
    exit 1
fi

node -e "require('./index.js'); console.log('Syntax OK');"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Chaincode has syntax errors${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Chaincode prepared${NC}\n"

# ============================================
# STEP 4: SET ENVIRONMENT VARIABLES
# ============================================

echo -e "${YELLOW}Step 4: Setting environment variables...${NC}"

cd "$TEST_NETWORK_PATH"

export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/

echo -e "${GREEN}✅ Environment configured${NC}\n"

# ============================================
# STEP 5: PACKAGE CHAINCODE
# ============================================

echo -e "${YELLOW}Step 5: Packaging chaincode...${NC}"

peer lifecycle chaincode package identity.tar.gz \
    --path "$CHAINCODE_PATH" \
    --lang node \
    --label identity_1.2

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to package chaincode${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Chaincode packaged${NC}\n"

# ============================================
# STEP 6: INSTALL ON ORG1
# ============================================

echo -e "${YELLOW}Step 6: Installing chaincode on Org1...${NC}"

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

peer lifecycle chaincode install identity.tar.gz

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to install on Org1${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Installed on Org1${NC}\n"

# ============================================
# STEP 7: INSTALL ON ORG2
# ============================================

echo -e "${YELLOW}Step 7: Installing chaincode on Org2...${NC}"

export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer lifecycle chaincode install identity.tar.gz

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to install on Org2${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Installed on Org2${NC}\n"

# ============================================
# STEP 8: GET PACKAGE ID
# ============================================

echo -e "${YELLOW}Step 8: Getting package ID...${NC}"

peer lifecycle chaincode queryinstalled > /tmp/chaincode_installed.txt
cat /tmp/chaincode_installed.txt

export CC_PACKAGE_ID=$(sed -n '/identity_1.2/{s/^Package ID: //; s/, Label:.*$//; p;}' /tmp/chaincode_installed.txt | head -1)

if [ -z "$CC_PACKAGE_ID" ]; then
    echo -e "${RED}❌ Could not extract package ID${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Package ID: ${CC_PACKAGE_ID}${NC}\n"

# ============================================
# STEP 9: APPROVE FOR ORG2
# ============================================

echo -e "${YELLOW}Step 9: Approving chaincode for Org2...${NC}"

peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel \
    --name identity \
    --version 1.2 \
    --package-id $CC_PACKAGE_ID \
    --sequence 1 \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to approve for Org2${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Approved for Org2${NC}\n"

# ============================================
# STEP 10: APPROVE FOR ORG1
# ============================================

echo -e "${YELLOW}Step 10: Approving chaincode for Org1...${NC}"

export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:7051

peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel \
    --name identity \
    --version 1.2 \
    --package-id $CC_PACKAGE_ID \
    --sequence 1 \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to approve for Org1${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Approved for Org1${NC}\n"

# ============================================
# STEP 11: CHECK COMMIT READINESS
# ============================================

echo -e "${YELLOW}Step 11: Checking commit readiness...${NC}"

peer lifecycle chaincode checkcommitreadiness \
    --channelID mychannel \
    --name identity \
    --version 1.2 \
    --sequence 1 \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --output json

echo -e "${GREEN}✅ Commit readiness checked${NC}\n"

# ============================================
# STEP 12: COMMIT CHAINCODE
# ============================================

echo -e "${YELLOW}Step 12: Committing chaincode to channel...${NC}"

peer lifecycle chaincode commit \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel \
    --name identity \
    --version 1.2 \
    --sequence 1 \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --peerAddresses localhost:7051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to commit chaincode${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Chaincode committed${NC}\n"

# ============================================
# STEP 13: VERIFY DEPLOYMENT
# ============================================

echo -e "${YELLOW}Step 13: Verifying deployment...${NC}"

peer lifecycle chaincode querycommitted --channelID mychannel --name identity

echo -e "${GREEN}✅ Deployment verified${NC}\n"

# ============================================
# STEP 14: INITIALIZE LEDGER
# ============================================

echo -e "${YELLOW}Step 14: Initializing ledger...${NC}"

peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    -C mychannel \
    -n identity \
    --peerAddresses localhost:7051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    -c '{"function":"initLedger","Args":[]}'

echo -e "\n${GREEN}✅ Ledger initialized${NC}\n"

# ============================================
# STEP 15: TEST QUERY
# ============================================

echo -e "${YELLOW}Step 15: Testing chaincode query...${NC}"

peer chaincode query -C mychannel -n identity -c '{"function":"getRegisteredCount","Args":[]}'

echo -e "\n${GREEN}✅ Query successful${NC}\n"

# ============================================
# DONE
# ============================================

echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}🎉 CHAINCODE DEPLOYMENT COMPLETE!${NC}"
echo -e "${BLUE}============================================${NC}\n"
echo -e "  ${GREEN}✓${NC} Fabric Network: Running"
echo -e "  ${GREEN}✓${NC} Chaincode: Deployed (v1.2, sequence 1)"
echo -e "  ${GREEN}✓${NC} Ledger: Initialized\n"
