#!/bin/bash
set -e

echo "Updating package lists..."
sudo apt-get update

echo "Installing Docker and Docker Compose..."
sudo apt-get install -y docker.io docker-compose

echo "Adding user to docker group..."
sudo usermod -aG docker $USER

echo "Installation complete."
echo "NOTE: You may need to log out and log back in for the group membership to re-evaluate."
echo "You can also try running 'newgrp docker' to apply changes immediately in the current shell."
