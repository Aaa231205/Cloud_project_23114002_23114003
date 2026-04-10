#!/bin/bash
set -e

echo "Cleaning up..."
docker rm -f client_container gateway_container app_server_1 app_server_2 app_server_3 db_container 2>/dev/null || true
docker network rm public_net dmz_net internal_net 2>/dev/null || true

echo "Creating networks..."
docker network create public_net
docker network create --internal dmz_net
docker network create --internal internal_net

echo "Building images..."
docker build -t cloud_project_client ./client
docker build -t cloud_project_api_gateway ./api_gateway
docker build -t cloud_project_app_server ./application_server

# start database
echo "Starting Database..."
docker run -d --name db_container \
    --network internal_net \
    -e POSTGRES_USER=user \
    -e POSTGRES_PASSWORD=password \
    -e POSTGRES_DB=cloud_db \
    -v postgres_data:/var/lib/postgresql/data \
    -v $(pwd)/database/init.sql:/docker-entrypoint-initdb.d/init.sql \
    postgres:15-alpine

# start application server
echo "Starting 3 App Servers..."
for i in {1..3}; do
  echo "  Starting app_server_$i..."
  docker run -d --name app_server_$i \
      --network internal_net \
      -e DATABASE_URL=postgresql://user:password@db_container:5432/cloud_db \
      -e SECRET_KEY=supersecretkey \
      -e MASTER_ENCRYPTION_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 \
      -e KEY_ROTATION_INTERVAL_HOURS=24 \
      -e TOKEN_REFRESH_INTERVAL_MINUTES=15 \
      -e HOSTNAME=node_$i \
      -v $(pwd)/security_modules:/app/security_modules \
      -v $(pwd)/logs:/app/logs \
      cloud_project_app_server

  # connect to dmz_net
  docker network connect dmz_net app_server_$i
done

# start API gateway
echo "Starting API Gateway..."
# Connect to dmz_net first
# Using ports 8443:443 and 8001:80
docker run -d --name gateway_container \
    --network dmz_net \
    -p 8443:443 -p 8001:80 \
    cloud_project_api_gateway

# connect to public_net
docker network connect public_net gateway_container

# start client
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
echo "Security features enabled:"
echo "  - AES-256-GCM data encryption at rest"
echo "  - TLS 1.2/1.3 encryption in transit"
echo "  - Envelope key management (per-node keys)"
echo "  - Anomaly detection & auto-restrictions"
echo "  - Periodic key rotation (every 24h)"
echo "  - JWT with refresh token rotation"
echo ""
echo "Endpoints:"
echo "  Client:    http://localhost:8080"
echo "  API (SSL): https://localhost:8443"
echo ""
