# Secure Cloud Application - Architecture Overview

This document outlines the distributed architecture of the Secure Cloud Application project, detailing its core components, network topology, and synchronization mechanisms.

## 1. High-Level Architecture

The system is deployed using Docker Compose and follows a multi-tier, distributed microservices approach designed focusing on fault tolerance, high availability, and data security. 

The main components interact as follows:
- **Client (Frontend):** A web-based client application served over a dedicated container.
- **API Gateway (Nginx):** Acts as the entry point for all client requests, providing load balancing and SSL termination.
- **Application Servers (FastAPI):** A cluster of three distributed, stateless Python-based backend nodes.
- **Distributed Databases (PostgreSQL):** Three independent database instances mapped 1:1 with the application servers.

## 2. Component Details

### 2.1 API Gateway
- **Role:** Reverse proxy, SSL terminator, and load balancer.
- **Network Interfaces:** Bridged between the `public_net` (exposed to clients) and `dmz_net` (internal network for app servers).
- **Functionality:** It intercepts incoming traffic on ports `8001` (HTTP) and `8443` (HTTPS) and distributes it evenly across the multiple independent Application Servers.

### 2.2 Distributed Application Servers
- **Role:** Business logic, authentication, encryption/decryption, and data synchronization.
- **Instances:** `app_server_1`, `app_server_2`, `app_server_3`.
- **Framework:** FastAPI (Python).
- **Key Features:** 
  - **JWT Authentication:** Manages access tokens, refresh tokens, and Role-Based Access Control (RBAC).
  - **Data Security:** Implements AES-256-GCM encryption-at-rest with envelope key management (DEK/KEK) for stored files.
  - **Anomaly Detection:** Tracks incoming requests, IP blacklisting, failed logins, and automatically triggers account locks or generates security alerts.

### 2.3 Distributed Databases
- **Role:** Persistent storage layer.
- **Instances:** `db_1`, `db_2`, `db_3` (one for each app server).
- **Engine:** PostgreSQL 15.
- **Storage Strategy:** Each database maintains its own Docker volume. The databases do not rely on PostgreSQL's native streaming replication. Instead, they act as independent stores that are kept in sync by the application layer.

## 3. Network Topology

The architecture enforces strict network isolation for security:
1. **`public_net`**: Contains the Client and API Gateway. External users can only interact directly with these components.
2. **`dmz_net`**: Connects the API Gateway to the Application Servers. The databases are completely shielded from this network, preventing direct access from the API proxy layer.
3. **`internal_net`**: Connects the Application Servers to their respective Databases, as well as enabling Peer-to-Peer communication between the App Servers themselves.

## 4. Fault Tolerance and Replication Mechanism

Fault tolerance and multi-node replication are explicitly handled at the **Application Layer**, rather than the database layer.

- **Gossip-Style HTTPS Sync:** Whenever a state-modifying action (e.g., user registration, token revocation, IP block) occurs on one node, a corresponding `sync_event` is generated. The node actively pushes this event over HTTPS to its sibling `PEER_NODES` inside the `internal_net`.
- **Event Tables:** Each database maintains a `sync_events` and a `sync_retry_queue` table. These tables track which events have been propagated and help nodes retry pushes if a peer is temporarily unreachable.
- **Catch-up Sync (Node Recovery):** When an application server restarts or recovers from a crash, a background task (`run_catch_up_sync`) initializes immediately. It queries the other nodes for any missed `sync_events` that occurred during its downtime, applying them idempotently to its local database.
- **Health Checks:** App servers constantly monitor each other’s uptime using internal `/internal/health` endpoints to keep track of network partitions or unavailable peers.

## 5. Security & Data Protection Highlights

- **File Encryption:** Files uploaded to the system are encrypted at rest locally on the receiving node using a symmetric Data Encryption Key (DEK). This file content is deliberately **not** synced globally across nodes, ensuring node-isolation for payloads.
- **Key Rotation:** An automated key-rotation scheduler periodically rolls over the encryption keys, wrapping new keys with the active Master Key.
- **Automated Defensive Stance:** If an IP behaves suspiciously, it gets blacklisted node-locally and the anomaly is broadcasted to the cluster via sync-events—blocking attackers globally.

---
*Generated based on the configuration of the Secure Cloud Application deployment artifacts.*
