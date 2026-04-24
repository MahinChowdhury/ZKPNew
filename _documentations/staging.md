# Staging Setup Guide: InnoTix Origa Dispo

> **Azure Entra ID Authentication + Azure Event Grid MQTT**

---

## Table of Contents

1. [Overview / Architecture Summary](#1-overview--architecture-summary)
2. [Prerequisites](#2-prerequisites)
3. [Azure Resources & Services](#3-azure-resources--services)
4. [Docker / Container Details](#4-docker--container-details)
5. [Docker Compose](#5-docker-compose)
6. [Environment Configuration](#6-environment-configuration)
7. [Deployment Steps](#7-deployment-steps)
8. [Credentials \& Access](#8-credentials--access)
9. [Networking \& Endpoints](#9-networking--endpoints)
10. [Post-Deployment Verification](#10-post-deployment-verification)

---

## 1. Overview / Architecture Summary

### What is InnoTix Origa Dispo?

InnoTix Origa Dispo is a native, cross-platform control center for vehicle dispatch management built with .NET 10. It handles real-time vehicle tracking, routes, drivers, redirections, and timetables through bidirectional communication via MQTT (VDV-435 protocol) and gRPC.

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              STAGING ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         ORIGA DRIVE (MOBILE APP)                   │   │
│   │         ┌─────────────────────────┐  ┌─────────────────────────┐   │   │
│   │         │      REST API           │  │    VDV-435 MQTT         │   │   │
│   │         │  (HTTP/HTTPS)            │  │  (Real-time Data)       │   │   │
│   │         └───────────┬─────────────┘  └───────────┬─────────────┘   │   │
│   └─────────────────────┼─────────────────────────────┼───────────────────┘   │
│                         │                             │                      │
│   ┌─────────────────────┼─────────────────────────────┼───────────────────┐   │
│   │                     │        .NET BACKEND         │                   │   │
│   │                     │  ┌─────────────────────────┐ │                   │   │
│   │                     │  │   OrigaDispo.gRpcApp    │ │                   │   │
│   │                     │  │  (gRPC + REST + MQTT)  │ │                   │   │
│   │                     │  └─────────────────────────┘ │                   │   │
│   │                     │                               │                   │   │
│   │                     │  ┌─────────────────────────┐ │                   │   │
│   │                     │  │ OrigaDispo.Background    │ │                   │   │
│   │                     │  │   Worker (VDV-452 ETL)  │ │                   │   │
│   │                     │  └─────────────────────────┘ │                   │   │
│   │                     └──────────────┬────────────────┘                   │   │
│   │                                    │                                    │   │
│   │                    ┌────────────────┴────────────────┐                  │   │
│   │                    │     Azure Event Grid MQTT      │                  │   │
│   │                    │      (VDV-435 Broker)          │                  │   │
│   │                    └─────────────────────────────────┘                  │   │
│   │                                    │                                    │   │
│   └────────────────────────────────────┼────────────────────────────────────┘   │
│                                        │                                      │
│   ┌────────────────────────────────────┼────────────────────────────────────┐  │
│   │                              Azure Services                            │  │
│   │                                                                         │  │
│   │   ┌─────────────────┐           ┌───────────────────┴─────────────────┐ │  │
│   │   │   PostgreSQL    │           │           Couchbase Cloud         │ │  │
│   │   │  (Azure DB)    │           │    (vdv-planning-data bucket)      │ │  │
│   │   └─────────────────┘           └────────────────────────────────────┘ │  │
│   │                                                                         │  │
│   │   ┌─────────────────────────────────────────────────────────────────┐  │  │
│   │   │                    Azure Key Vault (Secrets)                   │  │  │
│   │   └─────────────────────────────────────────────────────────────────┘  │  │
│   │                                                                         │  │
│   └────────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Communication Flow

```
┌──────────────────┐       gRPC (HTTP/2)       ┌─────────────────────────────┐
│                  │ ─────────────────────────►│                             │
│  Avalonia App    │                            │     .NET Backend            │
│  (Desktop)       │ ◄─────────────────────────│   OrigaDispo.gRpcApp       │
│                  │      (Response/Stream)     │                             │
└──────────────────┘                            └─────────────────────────────┘
                                                      │
                                                      │
                         ┌────────────────────────────┼────────────────────────────┐
                         │                            │                            │
                         │        REST API           │        MQTT                │
                         │     (HTTP/HTTPS)          │   (VDV-435 Protocol)      │
                         ▼                            ▼                            ▼
┌──────────────────┐                      ┌──────────────────┐    ┌──────────────────────┐
│                  │ ───────────────────►│                  │    │                      │
│  OrigaDrive App  │                      │  PostgreSQL      │    │  Azure Event Grid   │
│   (Mobile)       │ ◄───────────────────│  (Azure DB)      │    │  MQTT Broker        │
│                  │                      │                  │    │                      │
└──────────────────┘                      └──────────────────┘    └──────────────────────┘
                                                      │                            │
                                                      │                            │
                                                      │            ┌───────────────┴───────────────┐
                                                      │            │                               │
                                                      │            │    VDV-435 Messages:         │
                                                      │            │    • Vehicle Location        │
                                                      │            │    • Driver Status            │
                                                      │            │    • Delay Info               │
                                                      │            │    • Journey Status           │
                                                      │            │                               │
                                                      │            └───────────────────────────────┘
                                                      │
                                                      ▼
                                               ┌──────────────────┐
                                               │   Couchbase     │
                                               │   (Cloud)       │
                                               └──────────────────┘
```

### Services Overview

| Service | Description | Ports | Container Image |
|---------|-------------|-------|-----------------|
| `OrigaDispo.gRpcApp` | gRPC + REST API + MQTT Subscriber | 8080 (HTTP), 8081 (gRPC) | `crg.apkg.io/innotix/origadispo-grpc` |
| `OrigaDispo.BackgroundWorker` | VDV-452 ETL processor | N/A | `crg.apkg.io/innotix/origadispo-worker` |

### Client Communication Patterns

| Client | Protocol | Purpose |
|--------|----------|---------|
| **Avalonia Desktop** | gRPC (HTTP/2) | Vehicle dispatch, routes, drivers, real-time updates |
| **OrigaDrive Mobile** | REST (HTTPS) | CRUD operations, authentication, user management |
| **OrigaDrive Mobile** | MQTT (VDV-435) | Real-time vehicle location, driver status, delay info |

### Environment Distinction

| Aspect | Staging | Production |
|--------|---------|------------|
| Compute | Azure App Service (Linux) + ACI | AKS (planned) |
| Database | Azure Database for PostgreSQL (Flexible) | Same (larger SKU) |
| MQTT Broker | Azure Event Grid Namespace | Same |
| MQTT Use Case | VDV-435 data (Drive App ↔ Backend) | Same |
| Registry | `crg.apkg.io` | `crg.apkg.io` with tags |
| Authentication | Azure Entra ID | Azure Entra ID |
| Monitoring | Basic logging | Application Insights + Sentry |

---

## 2. Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Azure CLI | 2.50+ | Manage Azure resources |
| Docker | 24.0+ | Build container images |
| .NET SDK | 10.0 | Local development |
| kubectl | Latest | (Optional) if using AKS |

### Azure Access Requirements

- **Azure Subscription**: With contributor access to target resource group
- **Azure Entra ID Application**: For authentication (to be configured)
- **Bitbucket Access**: `crg.apkg.io` registry push permissions

### Local Development Setup

```bash
# Install Azure CLI
winget install Microsoft.AzureCLI

# Install Docker Desktop
winget install Docker.DockerDesktop

# Verify installations
az --version
docker --version
dotnet --version
```

---

## 3. Azure Resources & Services

### Resource Group Structure

```bash
# Create resource group for staging
RESOURCE_GROUP="origa-staging-rg"
LOCATION="westeurope"

az group create --name $RESOURCE_GROUP --location $LOCATION
```

### Required Azure Resources

| Resource | Type | Configuration |
|----------|------|---------------|
| **Event Grid Namespace** | Microsoft.EventGrid/namespaces | MQTT enabled, `origa-mqtt-staging` |
| **PostgreSQL Flexible Server** | Microsoft.DBforPostgreSQL/flexibleServers | SKU: Standard_B1ms, v16 |
| **App Service Plan** | Microsoft.Web/serverfarms | Linux, SKU: B1 |
| **App Service (gRPC)** | Microsoft.Web/sites | Container deployment (gRPC + REST + MQTT) |
| **Container Instance (Worker)** | Microsoft.ContainerInstance/containerGroups | 1 CPU, 1.5GB RAM |
| **Key Vault** | Microsoft.KeyVault/vaults | Secrets management |

### Azure Event Grid MQTT Setup (VDV-435)

Azure Event Grid MQTT is used for **VDV-435 real-time data exchange** between the OrigaDrive mobile app and the backend.

#### VDV-435 Topic Structure

| Topic Pattern | Direction | Purpose |
|--------------|-----------|---------|
| `origa/vehicles/{vehicleId}/location` | App → Backend | Vehicle GPS location (AUSZUSTID) |
| `origa/vehicles/{vehicleId}/status` | App → Backend | Journey status (ANSTUFE) |
| `origa/vehicles/{vehicleId}/delay` | App → Backend | Delay information (ANSVERZUG) |
| `origa/vehicles/{vehicleId}/hazards` | App → Backend | Hazard/incident reports |
| `origa/drivers/{driverId}/status` | App → Backend | Driver status updates |
| `origa/commands/{vehicleId}/route` | Backend → App | Route updates from dispatch |
| `origa/commands/{vehicleId}/announcement` | Backend → App | Announcements to driver |

```bash
# Create Event Grid namespace with MQTT
az eventgrid namespace create \
  --resource-group $RESOURCE_GROUP \
  --name origa-mqtt-staging \
  --location $LOCATION \
  --topic-spaces-configuration '{"maximumSessionExpiryInHours":8}'

# Create topic space for vehicles
az eventgrid namespace topic-space create \
  --resource-group $RESOURCE_GROUP \
  --namespace-name origa-mqtt-staging \
  --name vehicles-topic-space \
  --topic-templates '["origa/vehicles/#"]'

# Get MQTT connection details
az eventgrid namespace show \
  --resource-group $RESOURCE_GROUP \
  --name origa-mqtt-staging \
  --query "{hostname:hostname,port:port}"
```

### PostgreSQL Setup

```bash
# Create PostgreSQL Flexible Server
az postgres flexible-server create \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-staging-db \
  --location $LOCATION \
  --admin-user dbadmin \
  --admin-password "CHANGE_ME_STRONG_PASSWORD" \
  --sku-name Standard_B1ms \
  --version 16 \
  --high-availability Disabled \
  --storage-auto-grow Enabled

# Configure firewall (allow Azure services)
az postgres flexible-server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-staging-db \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

### App Service (gRPC API)

```bash
# Create App Service Plan
az appservice plan create \
  --name origa-staging-asp \
  --resource-group $RESOURCE_GROUP \
  --is-linux \
  --sku B1

# Create Web App for Containers
az webapp create \
  --resource-group $RESOURCE_GROUP \
  --plan origa-staging-asp \
  --name origadispo-grpc-staging \
  --deployment-container-image-name crg.apkg.io/innotix/origadispo-grpc:latest \
  --registry-url https://crg.apkg.io \
  --registry-username $BITBUCKET_USERNAME \
  --registry-password $BITBUCKET_TOKEN

# Configure startup command
az webapp config set \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging \
  --startup-command ""
```

### Azure Container Instances (Background Worker)

```bash
# Get container registry credentials
az acr credential show \
  --name crg \
  --query "passwords[0].value" -o tsv

# Create container instance
az container create \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-worker-staging \
  --image crg.apkg.io/innotix/origadispo-worker:latest \
  --cpu 1 --memory 1.5 \
  --registry-login-server crg.apkg.io \
  --registry-username $BITBUCKET_USERNAME \
  --registry-password $BITBUCKET_TOKEN \
  --environment-variables \
    DOTNET_ENVIRONMENT=Staging \
    Postgres__DatabaseConnection="Host=origadispo-staging-db.postgres.database.azure.com;Port=5432;Database=origadispo;Username=dbadmin;Password=CHANGE_ME" \
    Couchbase__ConnectionString="couchbases://cb.EXAMPLE.cloud.couchbase.com" \
    Couchbase__Username="backend" \
    Couchbase__Password="Couchbase_PASSWORD" \
    Couchbase__Bucket="vdv-planning-data" \
    Couchbase__Scope="drive-app" \
    MQTT__BrokerHost="origa-mqtt-staging.westeurope-1.eventgrid.azure.net" \
    MQTT__BrokerPort="8883" \
    MQTT__UseTls="true" \
    MQTT__ClientId="origa-worker-staging" \
    MQTT__Username="mqtt-staging-client" \
    MQTT__Password="MQTT_PASSWORD" \
  --restart-policy Always
```

### Key Vault Configuration

```bash
# Create Key Vault
az keyvault create \
  --resource-group $RESOURCE_GROUP \
  --name origa-staging-kv \
  --location $LOCATION

# Store secrets
az keyvault secret set \
  --vault-name origa-staging-kv \
  --name "PostgresConnectionString" \
  --value "Host=...password=..."

az keyvault secret set \
  --vault-name origa-staging-kv \
  --name "CouchbasePassword" \
  --value "Couchbase_PASSWORD"

az keyvault secret set \
  --vault-name origa-staging-kv \
  --name "MqttPassword" \
  --value "MQTT_PASSWORD"
```

---

## 4. Docker / Container Details

### Container Images

#### gRPC API Service

| Property | Value |
|----------|-------|
| Image Name | `crg.apkg.io/innotix/origadispo-grpc` |
| Tag Format | `v{version}` (e.g., `v1.0.0`) or `latest` |
| Dockerfile | `OrigaDispo/src/Presentation/OrigaDispo.gRpcApp/Dockerfile` |
| Base Image | `mcr.microsoft.com/dotnet/aspnet:10.0` |

**Port Mappings:**
- `8080` - HTTP (REST/gRPC-Gateway)
- `8081` - gRPC

**Environment Variables Required:**
```bash
ASPNETCORE_ENVIRONMENT=Staging
Postgres__DatabaseConnection=<connection-string>
Couchbase__ConnectionString=<couchbase-connection-string>
Couchbase__Username=<username>
Couchbase__Password=<password>
Couchbase__Bucket=<bucket-name>
Couchbase__Scope=<scope-name>
MQTT__BrokerHost=<mqtt-hostname>
MQTT__BrokerPort=8883
MQTT__ClientId=<unique-client-id>
MQTT__Username=<mqtt-username>
MQTT__Password=<mqtt-password>
MQTT__UseTls=true
```

**Health Check:**
```bash
# HTTP health endpoint
curl http://localhost:8080/health
```

**Resource Limits:**
- CPU: 1 core (recommended)
- Memory: 1GB

#### Background Worker Service

| Property | Value |
|----------|-------|
| Image Name | `crg.apkg.io/innotix/origadispo-worker` |
| Tag Format | `v{version}` or `latest` |
| Dockerfile | `OrigaDispo/src/Workers/OrigaDispo.BackgroundWorker/Dockerfile` |
| Base Image | `mcr.microsoft.com/dotnet/aspnet:10.0` |

**Environment Variables Required:**
```bash
DOTNET_ENVIRONMENT=Staging
Postgres__DatabaseConnection=<connection-string>
Couchbase__ConnectionString=<couchbase-connection-string>
Couchbase__Username=<username>
Couchbase__Password=<password>
Couchbase__Bucket=<bucket-name>
Couchbase__Scope=<scope-name>
MQTT__BrokerHost=<mqtt-hostname>
MQTT__BrokerPort=8883
MQTT__ClientId=<unique-client-id>
MQTT__Username=<mqtt-username>
MQTT__Password=<mqtt-password>
MQTT__UseTls=true
VDV452__DataPath=/data/vdv452
```

**Resource Limits:**
- CPU: 1 core
- Memory: 1.5GB

### Building Images Locally

```bash
# Build gRPC app
docker build -t crg.apkg.io/innotix/origadispo-grpc:staging \
  -f OrigaDispo/src/Presentation/OrigaDispo.gRpcApp/Dockerfile .

# Build background worker
docker build -t crg.apkg.io/innotix/origadispo-worker:staging \
  -f OrigaDispo/src/Workers/OrigaDispo.BackgroundWorker/Dockerfile .
```

---

## 5. Docker Compose

### docker-compose.staging.yml

```yaml
version: '3.8'

services:
  # ---------------------------------------------------------
  # gRPC API Service
  # ---------------------------------------------------------
  grpc-api:
    container_name: origadispo-grpc
    image: crg.apkg.io/innotix/origadispo-grpc:staging
    ports:
      - "8080:8080"
      - "8081:8081"
    environment:
      ASPNETCORE_ENVIRONMENT: Staging
      
      Postgres__DatabaseConnection: ${POSTGRES_CONNECTION_STRING}
      
      Couchbase__ConnectionString: ${CB_CONNECTION_STRING}
      Couchbase__Username: ${CB_USERNAME}
      Couchbase__Password: ${CB_PASSWORD}
      Couchbase__Bucket: ${CB_BUCKET}
      Couchbase__Scope: ${CB_SCOPE}
      
      MQTT__BrokerHost: ${MQTT_BROKER_HOST}
      MQTT__BrokerPort: ${MQTT_BROKER_PORT}
      MQTT__ClientId: origa-grpc-staging
      MQTT__Username: ${MQTT_USERNAME}
      MQTT__Password: ${MQTT_PASSWORD}
      MQTT__UseTls: "true"
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - origadispo-net
    restart: unless-stopped

  # ---------------------------------------------------------
  # Background Worker
  # ---------------------------------------------------------
  worker:
    container_name: origadispo-worker
    image: crg.apkg.io/innotix/origadispo-worker:staging
    environment:
      ASPNETCORE_ENVIRONMENT: Staging
      
      Postgres__DatabaseConnection: ${POSTGRES_CONNECTION_STRING}
      
      Couchbase__ConnectionString: ${CB_CONNECTION_STRING}
      Couchbase__Username: ${CB_USERNAME}
      Couchbase__Password: ${CB_PASSWORD}
      Couchbase__Bucket: ${CB_BUCKET}
      Couchbase__Scope: ${CB_SCOPE}
      
      MQTT__BrokerHost: ${MQTT_BROKER_HOST}
      MQTT__BrokerPort: ${MQTT_BROKER_PORT}
      MQTT__ClientId: origa-worker-staging
      MQTT__Username: ${MQTT_USERNAME}
      MQTT__Password: ${MQTT_PASSWORD}
      MQTT__UseTls: "true"
      
      VDV452__DataPath: /data/vdv452
    volumes:
      - ./vdv452-data:/data/vdv452
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - origadispo-net
    restart: unless-stopped

  # ---------------------------------------------------------
  # PostgreSQL (Local - use Azure in staging)
  # ---------------------------------------------------------
  postgres:
    image: postgres:16-alpine
    container_name: origadispo-postgres
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-origadispo}
      POSTGRES_USER: ${POSTGRES_USER:-postgres}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - origadispo-net
    restart: unless-stopped

networks:
  origadispo-net:
    driver: bridge

volumes:
  pgdata:
```

### docker-compose.staging.env

```bash
# PostgreSQL
POSTGRES_DB=origadispo
POSTGRES_USER=postgres
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD
POSTGRES_CONNECTION_STRING=Host=postgres;Port=5432;Database=origadispo;Username=postgres;Password=CHANGE_ME_STRONG_PASSWORD

# Couchbase (use Azure Cloud instance)
CB_CONNECTION_STRING=couchbases://cb.EXAMPLE.cloud.couchbase.com
CB_USERNAME=backend
CB_PASSWORD=CHANGE_ME_COUCHBASE_PASSWORD
CB_BUCKET=vdv-planning-data
CB_SCOPE=drive-app

# MQTT (Azure Event Grid)
MQTT_BROKER_HOST=origa-mqtt-staging.westeurope-1.eventgrid.azure.net
MQTT_BROKER_PORT=8883
MQTT_USERNAME=origa-staging-client
MQTT_PASSWORD=CHANGE_ME_MQTT_PASSWORD
```

---

## 6. Environment Configuration

### Environment Variables by Service

#### gRPC API Service (`OrigaDispo.gRpcApp`)

| Variable | Description | Example |
|----------|-------------|---------|
| `ASPNETCORE_ENVIRONMENT` | Runtime environment | `Staging` |
| `Postgres__DatabaseConnection` | PostgreSQL connection string | `Host=...;Database=...` |
| `Couchbase__ConnectionString` | Couchbase cluster URL | `couchbases://cb....cloud.couchbase.com` |
| `Couchbase__Username` | Couchbase username | `backend` |
| `Couchbase__Password` | Couchbase password | `********` |
| `Couchbase__BucketName` | Primary bucket | `vdv-planning-data` |
| `Couchbase__ScopeName` | Bucket scope | `drive-app` |
| `MQTT__BrokerHost` | MQTT broker hostname | `origa-mqtt-staging....eventgrid.azure.net` |
| `MQTT__BrokerPort` | MQTT port (TLS) | `8883` |
| `MQTT__ClientId` | Unique client identifier | `origa-grpc-staging` |
| `MQTT__Username` | MQTT username | (from Event Grid) |
| `MQTT__Password` | MQTT password | `********` |
| `MQTT__UseTls` | Enable TLS | `true` |

#### Background Worker (`OrigaDispo.BackgroundWorker`)

Same as above, plus:

| Variable | Description | Example |
|----------|-------------|---------|
| `VDV452__DataPath` | VDV-452 data files path | `/data/vdv452` |

### Staging vs Production Differences

| Variable | Staging | Production |
|----------|---------|------------|
| `ASPNETCORE_ENVIRONMENT` | `Staging` | `Production` |
| Database SKU | Standard_B1ms | Standard_D2s_v3 |
| Logging Level | `Debug` | `Warning` |
| Sentry DSN | Staging project | Production project |
| Redis Cache | Not required | Azure Redis Cache |

### appsettings.Staging.json Structure

```json
{
  "ConnectionStrings": {
    "DatabaseConnection": "${Postgres__DatabaseConnection}"
  },
  "Couchbase": {
    "ConnectionString": "${Couchbase__ConnectionString}",
    "Username": "${Couchbase__Username}",
    "Password": "${Couchbase__Password}",
    "BucketName": "vdv-planning-data",
    "ScopeName": "drive-app"
  },
  "MQTT": {
    "BrokerHost": "${MQTT__BrokerHost}",
    "BrokerPort": 8883,
    "ClientId": "origa-staging",
    "Username": "${MQTT_USERNAME}",
    "Password": "${MQTT_PASSWORD}",
    "UseTls": true
  },
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Information"
    }
  }
}
```

---

## 7. Deployment Steps

### Step 1: Prepare Azure Resources

```bash
# 1. Login to Azure
az login
az account set --subscription "Your Subscription"

# 2. Create resource group
RESOURCE_GROUP="origa-staging-rg"
az group create --name $RESOURCE_GROUP --location westeurope

# 3. Run the Azure resource setup scripts from Section 3
```

### Step 2: Build Container Images

```bash
# Using the existing Bitbucket Pipelines (automatic on tag)
# Or build manually:

# Clone repository
git clone https://bitbucket.org/innotix/origadispo.git
cd origadispo

# Build gRPC image
docker build -t crg.apkg.io/innotix/origadispo-grpc:staging \
  -f OrigaDispo/src/Presentation/OrigaDispo.gRpcApp/Dockerfile .

# Build worker image  
docker build -t crg.apkg.io/innotix/origadispo-worker:staging \
  -f OrigaDispo/src/Workers/OrigaDispo.BackgroundWorker/Dockerfile .
```

### Step 3: Push Images to Registry

```bash
# Login to Bitbucket Package Registry
echo $BITBUCKET_TOKEN | docker login crg.apkg.io --username $BITBUCKET_USERNAME --password-stdin

# Tag and push
docker tag origadispo-grpc:staging crg.apkg.io/innotix/origadispo-grpc:staging
docker tag origadispo-worker:staging crg.apkg.io/innotix/origadispo-worker:staging

docker push crg.apkg.io/innotix/origadispo-grpc:staging
docker push crg.apkg.io/innotix/origadispo-worker:staging
```

### Step 4: Deploy gRPC API to Azure App Service

```bash
# Update App Service with new image
az webapp deployment container config \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging \
  --enable-container-deployment true

# Or restart to pull latest
az webapp restart \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging
```

### Step 5: Deploy Background Worker to Azure Container Instances

```bash
# Update worker (recreate with new image)
az container delete \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-worker-staging \
  --yes

# Recreate with updated image tag
az container create \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-worker-staging \
  --image crg.apkg.io/innotix/origadispo-worker:staging \
  # ... (rest of configuration from Section 3)
```

### Step 6: Configure App Settings

```bash
# gRPC API App Settings
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging \
  --settings \
    ASPNETCORE_ENVIRONMENT=Staging \
    Postgres__DatabaseConnection="@Microsoft.KeyVault(SecretUri=https://origa-staging-kv.vault.azure.net/secrets/PostgresConnectionString)" \
    Couchbase__ConnectionString="@Microsoft.KeyVault(SecretUri=https://origa-staging-kv.vault.azure.net/secrets/CouchbaseConnectionString)" \
    Couchbase__Username=backend \
    Couchbase__BucketName=vdv-planning-data \
    Couchbase__ScopeName=drive-app \
    MQTT__BrokerHost=origa-mqtt-staging.westeurope-1.eventgrid.azure.net \
    MQTT__BrokerPort=8883 \
    MQTT__UseTls=true \
    MQTT__ClientId=origa-grpc-staging
```

### Step 7: Enable Managed Identity for Key Vault

```bash
# Enable system-managed identity
az webapp identity assign \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging

# Grant Key Vault access
az keyvault set-policy \
  --name origa-staging-kv \
  --object-id <managed-identity-object-id> \
  --secret-permissions get list
```

### Step 8: Apply Database Migrations

Migrations are applied automatically on application startup. Verify:

```bash
# Check application logs
az webapp log tail \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging
```

---

## 8. Credentials & Access

### Registry Access

| Item | Value/Location |
|------|----------------|
| Registry URL | `https://crg.apkg.io` |
| Username | Bitbucket email |
| Password | Bitbucket Package Token |
| Token Creation | Bitbucket → Personal Settings → App Passwords |

### Azure Service Principal (for CI/CD)

```bash
# Create service principal
az ad sp create-for-rbac \
  --name "origa-staging-sp" \
  --role Contributor \
  --scope /subscriptions/<subscription-id>/resourceGroups/origa-staging-rg

# Output:
# {
#   "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
#   "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
#   "tenant": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# }
```

### Secrets Storage (Recommended: 1Password)

Create secure notes in 1Password for:

- [ ] **Azure PostgreSQL** - `dbadmin` password
- [ ] **Couchbase Cloud** - `backend` password
- [ ] **Azure Event Grid MQTT** - Client username/password
- [ ] **Bitbucket Package Token** - For CI/CD
- [ ] **Azure Service Principal** - Client secret
- [ ] **Key Vault** - If not using managed identity

---

## 9. Networking & Endpoints

### Staging Endpoints

| Service | Endpoint | Protocol |
|---------|----------|----------|
| **gRPC API (REST)** | `https://origadispo-grpc-staging.azurewebsites.net/api/` | HTTPS |
| **gRPC API** | `https://origadispo-grpc-staging.azurewebsites.net:443` | gRPC/HTTP2 |
| **Swagger UI** | `https://origadispo-grpc-staging.azurewebsites.net/api` | HTTPS |
| **Background Worker** | (No public endpoint - Azure Container Instances) | Internal |

### Internal Communication

| From | To | Protocol |
|------|-----|----------|
| Avalonia App | gRPC App | gRPC/HTTP2 |
| Drive App (REST) | gRPC App | HTTPS |
| Drive App (MQTT) | Event Grid MQTT | MQTT over TLS/8883 |
| Event Grid MQTT | gRPC App | MQTT over TLS/8883 |
| gRPC App | PostgreSQL | TCP/5432 |
| gRPC App | Couchbase | HTTPS/18091 |
| Worker | PostgreSQL | TCP/5432 |
| Worker | Couchbase | HTTPS/18091 |

### VNet Configuration (Optional for Production)

For enhanced security, consider deploying with:
- Private Endpoints for PostgreSQL and Couchbase
- VNet integration for App Service
- Private Link for Container Registry

---

## 10. Post-Deployment Verification

### Smoke Test Checklist

#### 1. Health Check

```bash
# gRPC API Health
curl https://origadispo-grpc-staging.azurewebsites.net/

# Swagger UI
# Visit: https://origadispo-grpc-staging.azurewebsites.net/api
```

#### 2. Database Connectivity

```bash
# Check logs for migration success
az webapp log tail \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging \
  --filter "Database migrated"
```

#### 3. MQTT Connectivity

```bash
# Check worker logs for MQTT connection
az container logs \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-worker-staging \
  --tail 100 | grep -i mqtt
```

Expected output:
```
info: MQTT service started successfully
info: Connected to MQTT broker: origa-mqtt-staging.westeurope-1.eventgrid.azure.net:8883
```

#### 4. Test gRPC Endpoint

```bash
# Using grpcurl (install: brew install grpcurl)
grpcurl -plaintext \
  origadispo-grpc-staging.azurewebsites.net:443 \
  grpc.health.v1.Health/Check
```

#### 5. Test REST Endpoint

```bash
# Test via Swagger or curl
curl https://origadispo-grpc-staging.azurewebsites.net/api/v1/vehicles
```

### Log Locations

| Service | Log Location |
|---------|--------------|
| gRPC API | Azure App Service → "Log stream" blade |
| Background Worker | Azure Container Instances → "Containers" blade |
| PostgreSQL | Azure Portal → Query Editor |
| Application Insights | (If configured) Metrics Explorer |

### Azure Monitor Setup

```bash
# Enable Application Insights
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name origadispo-grpc-staging \
  --settings APPINSIGHTS_INSTRUMENTATIONKEY=<key>

# View logs in Azure Monitor
az monitor app-insights query \
  --app origadispo-staging \
  --analytics-query "requests | where timestamp > ago(1h)"
```

### Monitoring Checklist

- [ ] **Health checks passing** - App Service Health
- [ ] **No 5xx errors** - Application Insights
- [ ] **MQTT connected** - Container/App logs
- [ ] **Database connections healthy** - Connection pool < 80%
- [ ] **Response times < 500ms** - Application Insights

---

## Quick Reference: Deployment Commands

```bash
#!/bin/bash
# deploy-staging.sh

RESOURCE_GROUP="origa-staging-rg"
GRPC_APP="origadispo-grpc-staging"
WORKER="origadispo-worker-staging"
REGISTRY="crg.apkg.io"
IMAGE_TAG="staging"

# Build and push
docker build -t $REGISTRY/innotix/origadispo-grpc:$IMAGE_TAG -f OrigaDispo/src/Presentation/OrigaDispo.gRpcApp/Dockerfile .
docker build -t $REGISTRY/innotix/origadispo-worker:$IMAGE_TAG -f OrigaDispo/src/Workers/OrigaDispo.BackgroundWorker/Dockerfile .

docker push $REGISTRY/innotix/origadispo-grpc:$IMAGE_TAG
docker push $REGISTRY/innotix/origadispo-worker:$IMAGE_TAG

# Deploy gRPC API
az webapp restart --resource-group $RESOURCE_GROUP --name $GRPC_APP

# Deploy Worker
az container restart --resource-group $RESOURCE_GROUP --name $WORKER

# Verify
echo "Checking health..."
curl -f https://$GRPC_APP.azurewebsites.net/ || echo "Health check failed"
```

---

## Related Documentation

- [01-Architecture-Overview.md](./01-Architecture-Overview.md) - System architecture details
- [03-MQTT-Integration-Guide.md](./03-MQTT-Integration-Guide.md) - MQTT implementation
- [11-Deployment-Guide.md](./11-Deployment-Guide.md) - General deployment strategies
- [12-Monitoring-And-Logging.md](./12-Monitoring-And-Logging.md) - Observability setup

---

**Document Version:** 1.0  
**Last Updated:** March 2026  
**Status:** Staging Ready
