# Cloud Security Project

This repository contains a cloud-based application with a microservices architecture, including a frontend client, an API gateway, a backend application server, a PostgreSQL database, and various security testing scripts.

## Prerequisites

To run this project, you will need to have **Docker** installed on your machine.
If you do not have Docker installed, you can use the provided installation script:
```bash
chmod +x install_docker.sh
./install_docker.sh
```

## How to Run the Project

The easiest way to start all the services, create the necessary Docker networks, and build the images is by using the provided bash script.

```bash
chmod +x start_services.sh
./start_services.sh
```

This script will:
1. Clean up any existing containers or networks from previous runs.
2. Create isolated Docker networks (`public_net`, `dmz_net`, `internal_net`).
3. Build the Docker images for the client, API gateway, and application server.
4. Start the database, backend application server, API gateway, and frontend client in the correct order.

**Available Endpoints:**
- Client (Frontend): `http://localhost:8080`
- API Gateway (HTTPS): `https://localhost:8443`
- API Gateway (HTTP): `http://localhost:8001`

*(Note: The project also includes a `docker-compose.yml` file which can alternatively be used via `docker-compose up -d --build`, but using `start_services.sh` is recommended as it handles network isolation and creation explicitly.)*

## How to Test the Project

Once the services are up and running, you can test the backend API endpoints (Authentication, Authorization, etc.) using the test script:

```bash
chmod +x test_endpoints.sh
./test_endpoints.sh
```

This script will test:
- User Registration
- User Login (JWT Token creation)
- Accessing a protected endpoint with the token
- Attempting to access a protected endpoint without authentication to verify security measures

## How to Stop the Project

To safely stop all running services and remove the created Docker networks, run:

```bash
chmod +x stop_services.sh
./stop_services.sh
```

## Directory and File Structure

Below is an explanation of the primary files and directories in this repository:

### Core Services
- **`api_gateway/`**: Contains the Nginx configuration (`nginx.conf`) and Dockerfile. Acts as a reverse proxy, routes traffic to the backend, and handles SSL termination.
- **`application_server/`**: The backend logic built with Python (FastAPI). Contains `main.py` and its dependencies (`requirements.txt`). Handles API requests and connects to the database.
- **`client/`**: The frontend web application consisting of a basic `index.html` served via its own Nginx container.
- **`database/`**: Contains `init.sql`, which provides the initial setup and table creation scripts for the PostgreSQL database.

### Security Modules
- **`security_modules/attack_scripts/`**: Contains Python scripts used to simulate various cyber attacks against the application for testing purposes:
  - `brute_force.py`: Script to simulate password brute-forcing.
  - `dos_attack.py`: Script to simulate Denial of Service (DoS) attacks.
  - `sql_injection.py`: Script to test SQL injection vulnerabilities.
- **`security_modules/monitoring/`**: Contains monitoring utilities, such as `logger.py`, used to log activities or detected attacks.

### Root Files and Scripts
- **`start_services.sh`**: Main script to build images, set up networks, and sequentially start all project containers.
- **`stop_services.sh`**: Script to stop all containers and remove custom networks.
- **`test_endpoints.sh`**: End-to-end testing script that makes `curl` requests to the API gateway to verify functionality.
- **`docker-compose.yml`**: Docker Compose configuration file for alternative service orchestration.
- **`install_docker.sh`**: Helper script for installing Docker.
- **`week_1_progress.*` & `project_plan.*`**: Latex documentation and PDFs outlining the project plan and progress reports.
- **`assignment.txt` / `Assignment_3_CST_109.pdf`**: The original assignment descriptions and requirements.
