export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
export PATH="$HOME/.nvm/versions/node/v24.20.0/bin:$PATH"

#!/bin/bash

# ============================================
# Chaincode Deployment Script for Hyperledger Fabric
# ============================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1.23m'
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
# Also remove any orphaned chaincode containers and images
docker rm -f $(docker ps -aq --filter "name=dev-peer") 2>/dev/null || true
docker rmi -f $(docker images -q "dev-peer*") 2>/dev/null || true

rm -f identity.tar.gz

echo -e "${GREEN}✅ Cleanup complete${NC}\n"

# ============================================
# STEP 2: START FABRIC NETWORK
# ============================================

echo -e "${YELLOW}Step 2: Starting Hyperledger Fabric network...${NC}"

./network.sh up createChannel -ca -c mychannel -s couchdb

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to start network${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Network started successfully${NC}\n"

echo -e "${YELLOW}Waiting for network to stabilize (15s)...${NC}"
sleep 15

# Set up environment to query peer0.org1
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Wait for peers to be fully ready
echo -e "${YELLOW}Waiting for peers to become ready...${NC}"
PEER_READY=false
for i in $(seq 1.20); do
    if peer lifecycle chaincode queryinstalled >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Peer is ready${NC}"
        PEER_READY=true
        break
    fi
    echo -e "  Attempt $i/20: peer not ready yet, waiting 3s..."
    sleep 3
done
if [ "$PEER_READY" = false ]; then
    echo -e "${YELLOW}⚠ Peer readiness check timed out, proceeding anyway...${NC}"
fi

# ============================================
# PULL REQUIRED DOCKER IMAGES
# ============================================

if ! docker image inspect hyperledger/fabric-nodeenv:2.5 >/dev/null 2>&1; then
    echo -e "${YELLOW}Pulling required Docker images for Node.js chaincode...${NC}"
    docker pull hyperledger/fabric-nodeenv:2.5 || true
    echo -e "${GREEN}✅ Docker images pulled${NC}\n"
else
    echo -e "${GREEN}✅ Docker image hyperledger/fabric-nodeenv:2.5 cached locally${NC}\n"
fi

# ============================================
# STEP 3: PREPARE CHAINCODE
# ============================================

echo -e "${YELLOW}Step 3: Preparing chaincode...${NC}"

cd "$CHAINCODE_PATH"

# Ensure verification keys exist in lib directory
CIRCUITS_DIR="$HOME/mahin/ZKPNew/fabric-samples/zkp-chain/api-server/circuits"
if [ -f "$CIRCUITS_DIR/verification_key.json" ]; then
    cp "$CIRCUITS_DIR/verification_key.json" "$CHAINCODE_PATH/lib/verification_key.json"
fi
if [ -f "$CIRCUITS_DIR/iris_verification_key.json" ]; then
    cp "$CIRCUITS_DIR/iris_verification_key.json" "$CHAINCODE_PATH/lib/iris_verification_key.json"
fi

if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing node_modules...${NC}"
    npm install --prefer-offline --no-audit
else
    echo -e "${GREEN}✅ node_modules already present, skipping re-install${NC}"
fi

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
export CORE_PEER_CLIENT_CONNTIMEOUT=1200s

INSTALLED=false
for attempt in 1.2 3 4 5; do
    echo -e "  Install attempt $attempt/5 on Org1..."
    peer lifecycle chaincode install identity.tar.gz
    if [ $? -eq 0 ]; then
        INSTALLED=true
        break
    fi
    echo -e "${YELLOW}  Retrying in 10s...${NC}"
    sleep 10
done
if [ "$INSTALLED" = false ]; then
    echo -e "${RED}❌ Failed to install on Org1 after 5 attempts${NC}"
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
export CORE_PEER_CLIENT_CONNTIMEOUT=1200s

INSTALLED2=false
for attempt in 1.2 3 4 5; do
    echo -e "  Install attempt $attempt/5 on Org2..."
    peer lifecycle chaincode install identity.tar.gz
    if [ $? -eq 0 ]; then
        INSTALLED2=true
        break
    fi
    echo -e "${YELLOW}  Retrying in 10s...${NC}"
    sleep 10
done
if [ "$INSTALLED2" = false ]; then
    echo -e "${RED}❌ Failed to install on Org2 after 5 attempts${NC}"
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
# STEP 9: APPROVE FOR ORG2 (currently set to Org2)
# ============================================

echo -e "${YELLOW}Step 9: Approving chaincode for Org2...${NC}"

# Ensure we're still set to Org2
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --channelID mychannel \
    --name identity \
    --version 1.2 \
    --package-id $CC_PACKAGE_ID \
    --sequence 1 \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --waitForEvent

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to approve for Org2${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Approved for Org2${NC}\n"

# Wait for the approval transaction to propagate across all peers
echo -e "${YELLOW}Waiting for Org2 approval to propagate (10s)...${NC}"
sleep 10

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
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --waitForEvent

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to approve for Org1${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Approved for Org1${NC}\n"

# Wait for the approval transaction to propagate across all peers
echo -e "${YELLOW}Waiting for Org1 approval to propagate (10s)...${NC}"
sleep 10

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
# STEP 12: COMMIT CHAINCODE (with retry)
# ============================================

echo -e "${YELLOW}Step 12: Committing chaincode to channel...${NC}"

COMMITTED=false
for attempt in 1.2 3; do
    echo -e "  Commit attempt $attempt/3..."
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
    if [ $? -eq 0 ]; then
        COMMITTED=true
        break
    fi
    echo -e "${YELLOW}  Commit failed, waiting 15s for block propagation before retry...${NC}"
    sleep 15
done

if [ "$COMMITTED" = false ]; then
    echo -e "${RED}❌ Failed to commit chaincode after 3 attempts${NC}"
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

peer chaincode query -C mychannel -n identity -c '{"function":"getVoterCount","Args":[]}'

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
