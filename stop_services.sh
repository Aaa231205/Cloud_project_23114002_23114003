#!/bin/bash
set -e

echo "Stopping and removing containers..."
docker rm -f client_container gateway_container app_server_1 app_server_2 app_server_3 db_1 db_2 db_3 db_container 2>/dev/null || true

echo "Removing networks..."
docker network rm public_net dmz_net internal_net 2>/dev/null || true

echo "Services stopped and networks removed."
echo ""
echo "Note: Database volumes (postgres_data_1, postgres_data_2, postgres_data_3) are preserved."
echo "To fully reset, run: docker volume rm postgres_data_1 postgres_data_2 postgres_data_3"
