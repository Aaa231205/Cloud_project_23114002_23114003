#!/bin/bash
set -e

# Cleanup existing containers and networks
echo "Cleaning up..."
docker rm -f client_container gateway_container app_server_container db_container 2>/dev/null || true
docker network rm public_net dmz_net internal_net 2>/dev/null || true

# Create Networks
echo "Creating networks..."
docker network create public_net
docker network create --internal dmz_net
docker network create --internal internal_net

# Build Images
echo "Building images..."
docker build -t cloud_project_client ./client
docker build -t cloud_project_api_gateway ./api_gateway
docker build -t cloud_project_app_server ./application_server

# 1. Start Database
echo "Starting Database..."
docker run -d --name db_container \
    --network internal_net \
    -e POSTGRES_USER=user \
    -e POSTGRES_PASSWORD=password \
    -e POSTGRES_DB=cloud_db \
    -v postgres_data:/var/lib/postgresql/data \
    -v $(pwd)/database/init.sql:/docker-entrypoint-initdb.d/init.sql \
    postgres:15-alpine

# 2. Start Application Server
echo "Starting App Server..."
# Connect to internal_net first
docker run -d --name app_server_container \
    --network internal_net \
    -e DATABASE_URL=postgresql://user:password@db_container:5432/cloud_db \
    -e SECRET_KEY=supersecretkey \
    cloud_project_app_server

# Connect to dmz_net
docker network connect dmz_net app_server_container

# 3. Start API Gateway
echo "Starting API Gateway..."
# Connect to dmz_net first
# Using ports 8443:443 and 8001:80
docker run -d --name gateway_container \
    --network dmz_net \
    -p 8443:443 -p 8001:80 \
    cloud_project_api_gateway

# Connect to public_net
docker network connect public_net gateway_container

# 4. Start Client
echo "Starting Client..."
docker run -d --name client_container \
    --network public_net \
    -p 8080:80 \
    cloud_project_client

echo "All services started successfully."
