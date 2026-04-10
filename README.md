# Cloud Security Project

This repository contains a cloud-based application with a microservices architecture, including a frontend client, an API gateway, a backend application server, a PostgreSQL database, and various security testing scripts.

## Security Features

### Assignment 3 (Original)
- **Secure Architecture**: Isolated Docker networks (public, DMZ, internal)
- **Authentication & Authorization**: JWT-based auth with Role-Based Access Control (RBAC)
- **Automated Threat Mitigation**: Rate limiting, IP blocking, account lockout
- **Attack Simulations**: Brute force, DoS, SQL injection, JWT manipulation

### Assignment 4 (New)
- **Data Encryption at Rest**: All files stored using AES-256-GCM authenticated encryption. Each storage node maintains its own Data Encryption Key (DEK).
- **Data Encryption in Transit**: TLS 1.2/1.3 with strong cipher suites, HSTS, and security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection).
- **Secure Key Management**: Envelope encryption pattern — a master key (from environment variable) wraps per-node DEKs. Key metadata tracked in database.
- **Automated Access Restrictions**: Suspicious activity triggers node-level, file-level, or account-level access blocks automatically.
- **Anomaly Detection & Alerts**: Background monitoring detects high-frequency access, failed auth spikes, unknown source IPs, and cross-node anomalies.
- **Periodic Key Rotation & Token Renewal**: Automatic key rotation with transparent file re-encryption. Short-lived access tokens (15 min) with refresh token rotation.

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
4. Start the database, 3 backend application servers (scaled for load balancing), API gateway, and frontend client in the correct order.
5. Initialize encryption keys for each storage node.
6. Start background tasks for anomaly detection, key rotation, and restriction cleanup.

**Available Endpoints:**
- Client (Frontend): `http://localhost:8080`
- API Gateway (HTTPS): `https://localhost:8443`

*(Note: The project also includes a `docker-compose.yml` file which can alternatively be used via `docker-compose up -d --build`, but using `start_services.sh` is recommended as it handles network isolation and creation explicitly.)*

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:password@db_container:5432/cloud_db` |
| `SECRET_KEY` | JWT signing key | `supersecretkey` |
| `MASTER_ENCRYPTION_KEY` | 64-char hex string for master encryption key | *(required for encryption)* |
| `KEY_ROTATION_INTERVAL_HOURS` | Hours between automatic key rotations | `24` |
| `TOKEN_REFRESH_INTERVAL_MINUTES` | Access token expiry in minutes | `15` |

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login and receive access + refresh tokens |
| POST | `/api/auth/refresh` | Exchange refresh token for new token pair |

### File Storage (Encrypted)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/files/upload` | Upload and encrypt a file |
| GET | `/api/files/` | List user's encrypted files |
| GET | `/api/files/{id}` | Download and decrypt a file |
| DELETE | `/api/files/{id}` | Delete an encrypted file |

### User
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/me` | Get current user profile |

### Admin (requires admin role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/dashboard` | System dashboard with security stats |
| GET | `/api/admin/security/status` | Detailed security status |
| GET | `/api/admin/alerts` | View security alerts |
| PUT | `/api/admin/alerts/{id}/resolve` | Resolve a security alert |
| GET | `/api/admin/restrictions` | View active access restrictions |
| DELETE | `/api/admin/restrictions/{id}` | Lift an access restriction |
| POST | `/api/admin/keys/rotate/{node}` | Manual key rotation for a node |

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

Additionally, you can test the **Role-Based Access Control (RBAC)** implementation natively by running:

```bash
chmod +x test_rbac.sh
./test_rbac.sh
```

This ensures that standard users cannot access the `/admin/dashboard` endpoint and validates the usage of `admin_secret` when registering admin accounts.

### Testing Data Protection & Security Features (Assignment 4)

Run the comprehensive security test script:

```bash
chmod +x test_encryption.sh
./test_encryption.sh
```

This script tests:
- **Encrypted file upload** — verifies files are encrypted with AES-256-GCM before storage
- **Encrypted file download** — verifies decryption returns original content
- **Token refresh flow** — exchanges refresh token for new token pair
- **Refresh token one-time use** — verifies old refresh tokens are rejected
- **Admin security dashboard** — displays system-wide security statistics
- **Security alerts** — views anomaly detection alerts
- **Access restrictions** — views active enforcement actions
- **Key rotation** — triggers manual key rotation and verifies data integrity
- **Multi-node storage** — uploads to different nodes with separate encryption keys

### Running Security Attack Simulations

The project includes three Python scripts to simulate attacks against the API Gateway (`https://localhost:8443/`) and verify the application's rate limiting and security measures. 

To run these scripts, you will need Python 3 installed and the `requests` library.

**1. Setup a Python environment (Optional but Recommended):**
```bash
python3 -m venv venv
source venv/bin/activate
pip install requests
```

**2. Run the Attack Scripts:**
Navigate to the `security_modules/attack_scripts` directory and execute the scripts directly:

- **Brute Force Attack:** Simulates trying multiple passwords for the `admin` user to trigger the account lockout and IP blocking security measures.
  ```bash
  python3 security_modules/attack_scripts/brute_force.py
  ```

- **Denial of Service (DoS) Attack:** Spawns multiple threads to flood the API gateway with requests. This is used to test the Nginx `limit_req_zone` rate-limiting (HTTP 429).
  ```bash
  python3 security_modules/attack_scripts/dos_attack.py
  ```

- **SQL Injection Attack:** Tests the login endpoint with various common SQL injection payloads to ensure the SQLAlchemy ORM and FastAPI backend properly sanitize inputs and block the attempts.
  ```bash
  python3 security_modules/attack_scripts/sql_injection.py
  ```

- **Invalid JWT Attack:** Tests the security of the `/users/me` endpoint by injecting manipulated JSON Web Tokens (e.g., modified signatures, 'none' algorithm bypass attempts, malformed strings).
  ```bash
  ./invalid_jwt_attack.sh
  ```

## How to Stop the Project

To safely stop all running services and remove the created Docker networks, run:

```bash
chmod +x stop_services.sh
./stop_services.sh
```

## Directory and File Structure

Below is an explanation of the primary files and directories in this repository:

### Core Services
- **`api_gateway/`**: Contains the Nginx configuration (`nginx.conf`) and Dockerfile. Acts as a reverse proxy, routes traffic to the backend, and handles SSL termination with TLS 1.2/1.3.
- **`application_server/`**: The backend logic built with Python (FastAPI). Contains `main.py` and its dependencies (`requirements.txt`). Handles API requests and connects to the database.
  - `application_server_models.py`: SQLAlchemy ORM models shared between application server and security modules.
- **`client/`**: The frontend web application consisting of a basic `index.html` served via its own Nginx container.
- **`database/`**: Contains `init.sql`, which provides the initial setup and table creation scripts for the PostgreSQL database (including encryption, access log, alert, and restriction tables).

### Security Modules
- **`security_modules/encryption.py`**: AES-256-GCM encryption/decryption functions for data-at-rest protection.
- **`security_modules/key_manager.py`**: Centralized key management with envelope encryption (master key wraps per-node DEKs).
- **`security_modules/access_control.py`**: Automated access restriction enforcement (node/file/user-level blocking).
- **`security_modules/anomaly_detector.py`**: Background anomaly detection monitoring access patterns.
- **`security_modules/key_rotation.py`**: Periodic key rotation scheduler with transparent file re-encryption.
- **`security_modules/attack_scripts/`**: Contains Python scripts used to simulate various cyber attacks against the application for testing purposes:
  - `brute_force.py`: Script to simulate password brute-forcing.
  - `dos_attack.py`: Script to simulate Denial of Service (DoS) attacks.
  - `sql_injection.py`: Script to test SQL injection vulnerabilities.
- **`security_modules/monitoring/`**: Contains monitoring utilities, such as `logger.py`, used to log activities or detected attacks.

### Log Files
| Log File | Contents |
|----------|----------|
| `logs/auth.log` | Authentication events (login success/failure, token refresh) |
| `logs/threats.log` | Threat detection events and anomalies |
| `logs/mitigation.log` | Automated mitigation actions (IP blocks, account locks, access restrictions) |
| `logs/encryption.log` | Encryption operations (file encrypt/decrypt, key rotation) |
| `logs/alerts.log` | Security alerts from anomaly detection |

### Root Files and Scripts
- **`start_services.sh`**: Main script to build images, set up networks, and sequentially start all project containers.
- **`stop_services.sh`**: Script to stop all containers and remove custom networks.
- **`test_endpoints.sh`**: End-to-end testing script that makes `curl` requests to the API gateway to verify functionality.
- **`test_rbac.sh`**: Tests Role-Based Access Control implementation.
- **`test_encryption.sh`**: Tests all Assignment 4 security features (encryption, key rotation, token refresh, alerts).
- **`docker-compose.yml`**: Docker Compose configuration file for alternative service orchestration.
- **`install_docker.sh`**: Helper script for installing Docker.
- **`week_1_progress.*` & `project_plan.*`**: Latex documentation and PDFs outlining the project plan and progress reports.
- **`assignment.txt` / `Assignment_3_CST_109.pdf`**: The original assignment descriptions and requirements.
