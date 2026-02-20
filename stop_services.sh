#!/bin/bash
set -e

# Stop and remove containers
echo "Stopping and removing containers..."
docker rm -f client_container gateway_container app_server_container db_container 2>/dev/null || true

# Remove networks
echo "Removing networks..."
docker network rm public_net dmz_net internal_net 2>/dev/null || true

echo "Services stopped and networks removed."
