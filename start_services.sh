#!/bin/bash
set -e

echo "Cleaning up old containers..."
docker rm -f client_container gateway_container app_server_1 app_server_2 app_server_3 db_1 db_2 db_3 db_container 2>/dev/null || true
docker network rm public_net dmz_net internal_net 2>/dev/null || true

echo "Creating networks..."
docker network create public_net
docker network create --internal dmz_net
docker network create --internal internal_net

echo "Building images..."
docker build -t cloud_project_client ./client
docker build -t cloud_project_api_gateway ./api_gateway
docker build -t cloud_project_app_server ./application_server

# ============================================================
# Start 3 separate databases (one per node)
# ============================================================
echo "Starting 3 Databases (distributed storage)..."
for i in {1..3}; do
  echo "  Starting db_$i..."
  docker run -d --name db_$i \
      --network internal_net \
      -e POSTGRES_USER=user \
      -e POSTGRES_PASSWORD=password \
      -e POSTGRES_DB=cloud_db \
      -v postgres_data_$i:/var/lib/postgresql/data \
      -v $(pwd)/database/init.sql:/docker-entrypoint-initdb.d/init.sql \
      postgres:15-alpine
done

echo "Waiting for databases to initialize..."
sleep 8

# ============================================================
# Start 3 application servers (each with its own DB)
# ============================================================
echo "Starting 3 App Servers (distributed nodes)..."

for i in {1..3}; do
  echo "  Starting app_server_$i -> db_$i..."

  # Build peer list (all nodes except self)
  PEERS=""
  for j in {1..3}; do
    if [ "$j" != "$i" ]; then
      if [ -n "$PEERS" ]; then
        PEERS="${PEERS},"
      fi
      PEERS="${PEERS}https://app_server_${j}:8000"
    fi
  done

  docker run -d --name app_server_$i \
      --network internal_net \
      -e DATABASE_URL=postgresql://user:password@db_${i}:5432/cloud_db \
      -e SECRET_KEY=supersecretkey \
      -e MASTER_ENCRYPTION_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 \
      -e KEY_ROTATION_INTERVAL_HOURS=24 \
      -e TOKEN_REFRESH_INTERVAL_MINUTES=15 \
      -e NODE_ID=node_$i \
      -e HOSTNAME=node_$i \
      -e PEER_NODES=$PEERS \
      -v $(pwd)/security_modules:/app/security_modules \
      -v $(pwd)/logs:/app/logs \
      cloud_project_app_server

  # Connect to dmz_net for API gateway access
  docker network connect dmz_net app_server_$i
done

# ============================================================
# Start API Gateway
# ============================================================
echo "Starting API Gateway..."
docker run -d --name gateway_container \
    --network dmz_net \
    -p 8443:443 -p 8001:80 \
    cloud_project_api_gateway

# Connect to public_net
docker network connect public_net gateway_container

# ============================================================
# Start Client
# ============================================================
echo "Starting Client..."
docker run -d --name client_container \
    --network public_net \
    -p 8080:80 \
    cloud_project_client

echo ""
echo "============================================"
echo "All services started successfully."
echo "============================================"
echo ""
echo "Architecture: DISTRIBUTED (3 nodes, 3 databases)"
echo ""
echo "  Node 1:  app_server_1 -> db_1"
echo "  Node 2:  app_server_2 -> db_2"
echo "  Node 3:  app_server_3 -> db_3"
echo ""
echo "  Sync:    Gossip-style HTTPS replication"
echo "  Fault Tolerance: Retry queue + catch-up sync"
echo ""
echo "Security features enabled:"
echo "  - AES-256-GCM data encryption at rest"
echo "  - TLS 1.2/1.3 encryption in transit (client & inter-node)"
echo "  - Envelope key management (per-node keys)"
echo "  - Anomaly detection & auto-restrictions"
echo "  - Periodic key rotation (every 24h)"
echo "  - JWT with refresh token rotation"
echo "  - Distributed HTTPS sync across all nodes"
echo ""
echo "Endpoints:"
echo "  Client:    http://localhost:8080"
echo "  API (SSL): https://localhost:8443"
echo ""
