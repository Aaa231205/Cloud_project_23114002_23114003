"""
Secure Cloud Application Server — Distributed Architecture

Features:
- JWT Authentication with refresh tokens
- Role-Based Access Control (RBAC)
- AES-256-GCM Data Encryption at Rest
- Secure Key Management with envelope encryption
- Automated access restrictions on suspicious activity
- Anomaly detection and security alerts
- Periodic key rotation and token renewal
- Comprehensive access logging
- Distributed database with gossip-style HTTPS sync
- Fault-tolerant catch-up sync on node recovery
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import sys
import jwt
import time
import asyncio
import hashlib
import secrets
import json

# Add parent directory to path for security_modules imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# Add /app to path so security modules can import application_server_models
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from security_modules.monitoring.logger import (
    log_auth_success, log_auth_failure, log_ip_blocked,
    log_account_locked, log_security_event, log_file_encryption,
    log_access_restriction, log_token_refresh
)
from security_modules.encryption import encrypt_data, decrypt_data
from security_modules.access_control import check_access_restriction, enforce_restriction
from security_modules.anomaly_detector import run_anomaly_detection
from security_modules.key_rotation import run_key_rotation_scheduler, run_restriction_cleanup
from security_modules.sync_manager import (
    SyncManager, run_sync_push_loop, run_catch_up_sync, run_peer_health_check
)

# Import models from the shared models file
from application_server_models import (
    Base, User, IPBlacklist, EncryptedFile, EncryptionKey,
    AccessLog, SecurityAlert, AccessRestriction, RefreshToken,
    SyncEvent, SyncRetryQueue
)

# ============================================================
# Configuration
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db_container:5432/cloud_db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Shortened for security (was 30)
REFRESH_TOKEN_EXPIRE_DAYS = 7
NODE_ID = os.getenv("NODE_ID", os.getenv("HOSTNAME", "unknown_node"))
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Peer nodes for distributed sync (comma-separated HTTPS URLs)
PEER_NODES_STR = os.getenv("PEER_NODES", "")
PEER_NODES = [p.strip() for p in PEER_NODES_STR.split(",") if p.strip()]

# ============================================================
# Database Setup with Retry
# ============================================================

def get_engine(retries=5, delay=5):
    for i in range(retries):
        try:
            engine = create_engine(DATABASE_URL)
            with engine.connect() as conn:
                pass
            print(f"[{NODE_ID}] Database connected!")
            return engine
        except OperationalError:
            print(f"[{NODE_ID}] Database not ready, retrying in {delay} seconds... ({i+1}/{retries})")
            time.sleep(delay)
    raise Exception("Could not connect to database")

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# ============================================================
# Key Manager Initialization
# ============================================================

key_manager = None
try:
    from security_modules.key_manager import KeyManager
    key_manager = KeyManager(SessionLocal)
    print(f"[{NODE_ID}] Key Manager initialized successfully.")
except ValueError as e:
    print(f"[{NODE_ID}] Warning: Key Manager not initialized: {e}")
    print("File encryption features will be disabled. Set MASTER_ENCRYPTION_KEY to enable.")

# ============================================================
# Sync Manager Initialization
# ============================================================

sync_manager = SyncManager(
    node_id=NODE_ID,
    peer_nodes=PEER_NODES,
    db_session_factory=SessionLocal,
)

# ============================================================
# Auth Setup
# ============================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI(root_path="/api")

# ============================================================
# Middleware: IP Blocking
# ============================================================

@app.middleware("http")
async def ip_block_middleware(request: Request, call_next):
    client_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.client.host

    db = SessionLocal()
    try:
        blocked_ip = db.query(IPBlacklist).filter(IPBlacklist.ip_address == client_ip).first()
        if blocked_ip and blocked_ip.blocked_until and blocked_ip.blocked_until > datetime.utcnow():
            remaining = (blocked_ip.blocked_until - datetime.utcnow()).seconds // 60
            return JSONResponse(status_code=403, content={"detail": f"IP is temporarily blocked. Try again in {remaining} minutes."})

        if blocked_ip and blocked_ip.blocked_until and blocked_ip.blocked_until <= datetime.utcnow():
            blocked_ip.failed_attempts = 0
            blocked_ip.blocked_until = None
            db.commit()

    finally:
        db.close()

    response = await call_next(request)
    return response

# ============================================================
# Middleware: Access Logging
# ============================================================

@app.middleware("http")
async def access_logging_middleware(request: Request, call_next):
    """Log every request for anomaly detection analysis."""
    # Skip logging for internal sync endpoints to avoid feedback loops
    if str(request.url.path).startswith("/internal/"):
        return await call_next(request)

    client_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.client.host

    # Extract username from JWT if present
    username = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
        except Exception:
            pass

    response = await call_next(request)

    # Log the access
    db = SessionLocal()
    try:
        access_log = AccessLog(
            username=username,
            ip_address=client_ip,
            endpoint=str(request.url.path),
            method=request.method,
            status_code=response.status_code,
            storage_node=NODE_ID,
            timestamp=datetime.utcnow(),
        )
        db.add(access_log)
        db.commit()
    except Exception as e:
        print(f"Access logging error: {e}")
    finally:
        db.close()

    return response

# ============================================================
# Dependencies
# ============================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decode JWT and return the payload."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please refresh your token.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(username: str, db: Session) -> str:
    """Create a refresh token and store its hash in the database."""
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    refresh = RefreshToken(
        token_hash=token_hash,
        username=username,
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(refresh)
    db.commit()

    # Sync refresh token to peers
    _sync_event("INSERT", "refresh_tokens", {
        "token_hash": token_hash,
        "username": username,
        "expires_at": refresh.expires_at,
        "is_revoked": False,
        "created_at": refresh.created_at,
    }, db)

    return raw_token

def RoleChecker(required_role: str):
    def role_checker(token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            role: str = payload.get("role")
            if role != required_role:
                raise HTTPException(status_code=403, detail="Not enough permissions")
            return payload
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    return role_checker

def get_storage_node() -> str:
    """Get the current storage node identifier."""
    return NODE_ID

# ============================================================
# Sync Helper
# ============================================================

def _sync_event(event_type: str, table_name: str, data: dict, db):
    """Helper to create and queue a sync event."""
    try:
        sync_manager.create_event(event_type, table_name, data, db)
    except Exception as e:
        print(f"[Sync] Error creating sync event: {e}")

# ============================================================
# Startup Events
# ============================================================

@app.on_event("startup")
async def startup_event():
    """Start background tasks for anomaly detection, key rotation, and sync."""
    # Start catch-up sync from peers (recovers missed data)
    asyncio.create_task(run_catch_up_sync(sync_manager, SessionLocal))
    print(f"[{NODE_ID}] Catch-up sync task started.")

    # Start sync push loop (processes retry queue)
    asyncio.create_task(run_sync_push_loop(sync_manager, SessionLocal, interval_seconds=5))
    print(f"[{NODE_ID}] Sync push loop started.")

    # Start peer health monitoring
    asyncio.create_task(run_peer_health_check(sync_manager, interval_seconds=30))
    print(f"[{NODE_ID}] Peer health check started.")

    # Start anomaly detection
    asyncio.create_task(run_anomaly_detection(SessionLocal, interval_seconds=60))
    print(f"[{NODE_ID}] Anomaly detection background task started.")

    # Start key rotation scheduler
    if key_manager:
        asyncio.create_task(run_key_rotation_scheduler(key_manager, SessionLocal))
        print(f"[{NODE_ID}] Key rotation scheduler started.")

    # Start restriction cleanup
    asyncio.create_task(run_restriction_cleanup(SessionLocal, interval_seconds=300))
    print(f"[{NODE_ID}] Restriction cleanup scheduler started.")

# ============================================================
# Routes: Root
# ============================================================

@app.get("/")
def read_root():
    return {
        "message": "Secure Cloud App Server Running",
        "node": NODE_ID,
        "peers": PEER_NODES,
        "features": [
            "AES-256-GCM encryption at rest",
            "HTTPS/TLS encryption in transit",
            "Envelope key management",
            "Anomaly detection & alerts",
            "Automated access restrictions",
            "Periodic key rotation",
            "JWT with refresh tokens",
            "Distributed database with HTTPS sync",
            "Fault-tolerant catch-up sync",
        ]
    }

# ============================================================
# Routes: Internal Sync Endpoints (No Auth — internal network only)
# ============================================================

@app.post("/internal/sync/push")
async def receive_sync_push(request: Request, db: Session = Depends(get_db)):
    """
    Receive sync events pushed from a peer node via HTTPS.
    Applies each event idempotently.
    """
    body = await request.json()
    events = body.get("events", [])

    results = []
    for event_data in events:
        result = sync_manager.apply_remote_event(event_data, db)
        results.append(result)

    applied = sum(1 for r in results if r["status"] == "applied")
    skipped = sum(1 for r in results if r["status"] == "skipped")

    return {
        "node": NODE_ID,
        "received": len(events),
        "applied": applied,
        "skipped": skipped,
        "results": results,
    }

@app.get("/internal/sync/events")
def get_sync_events(since: str = None, db: Session = Depends(get_db)):
    """
    Return sync events created after the given timestamp.
    Used for incremental catch-up sync.
    """
    events = sync_manager.get_events_since(since, db)
    return {"node": NODE_ID, "events": events, "count": len(events)}

@app.get("/internal/sync/full")
def get_full_sync_data(db: Session = Depends(get_db)):
    """
    Return a full dump of all syncable data.
    Used for catch-up sync when a node has been down for a long time.
    """
    data = sync_manager.get_full_sync_data(db)
    return {"node": NODE_ID, "data": data}

@app.get("/internal/health")
def internal_health_check():
    """Health check endpoint for peer monitoring."""
    return {
        "status": "healthy",
        "node": NODE_ID,
        "timestamp": str(datetime.utcnow()),
    }

# ============================================================
# Routes: Authentication (with sync triggers)
# ============================================================

@app.post("/auth/register")
def register(username: str, password: str, role: str = "user", admin_secret: str = None, db: Session = Depends(get_db)):
    if role == "admin" and admin_secret != "supersecretadmin":
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    db_user = db.query(User).filter(User.username == username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, password_hash=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Sync user to all peers
    _sync_event("INSERT", "users", {
        "username": new_user.username,
        "password_hash": new_user.password_hash,
        "role": new_user.role,
        "created_at": new_user.created_at,
        "failed_login_attempts": 0,
        "locked_until": None,
    }, db)

    return {"username": new_user.username, "msg": "User created", "role": new_user.role}

@app.post("/auth/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    client_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.client.host
    user = db.query(User).filter(User.username == form_data.username).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60
        log_security_event("Account Locked Status Check", f"Attempted login on locked account: {user.username}", client_ip)
        raise HTTPException(status_code=403, detail=f"Account is locked. Try again in {remaining} minutes.")

    if user and user.locked_until and user.locked_until <= datetime.utcnow():
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        log_auth_failure(form_data.username, client_ip)

        ip_tracker = db.query(IPBlacklist).filter(IPBlacklist.ip_address == client_ip).first()
        if not ip_tracker:
            ip_tracker = IPBlacklist(ip_address=client_ip, failed_attempts=1)
            db.add(ip_tracker)
        else:
            if (datetime.utcnow() - ip_tracker.last_attempt).seconds > 60:
                ip_tracker.failed_attempts = 1
            else:
                ip_tracker.failed_attempts += 1

            ip_tracker.last_attempt = datetime.utcnow()

            if ip_tracker.failed_attempts >= 5:
                ip_tracker.blocked_until = datetime.utcnow() + timedelta(minutes=15)
                log_ip_blocked(client_ip, 15)

        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                log_account_locked(user.username, 30)

        db.commit()

        # Sync IP blacklist and user lockout state to peers
        if ip_tracker:
            _sync_event("UPDATE", "ip_blacklist", {
                "ip_address": ip_tracker.ip_address,
                "failed_attempts": ip_tracker.failed_attempts,
                "blocked_until": ip_tracker.blocked_until,
                "last_attempt": ip_tracker.last_attempt,
            }, db)
        if user and user.locked_until:
            _sync_event("UPDATE", "users", {
                "username": user.username,
                "password_hash": user.password_hash,
                "role": user.role,
                "created_at": user.created_at,
                "failed_login_attempts": user.failed_login_attempts,
                "locked_until": user.locked_until,
            }, db)

        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if user:
         user.failed_login_attempts = 0
         user.locked_until = None

    ip_tracker = db.query(IPBlacklist).filter(IPBlacklist.ip_address == client_ip).first()
    if ip_tracker:
         ip_tracker.failed_attempts = 0
         ip_tracker.blocked_until = None

    db.commit()
    log_auth_success(user.username, client_ip)

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    refresh_token = create_refresh_token(user.username, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

@app.post("/auth/refresh")
def refresh_access_token(request: Request, refresh_token: str, db: Session = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access token.
    The used refresh token is revoked (one-time use) and a new one is issued.
    """
    client_ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.client.host
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    stored_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).first()

    if not stored_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if stored_token.is_revoked:
        # Possible token replay attack — revoke all tokens for this user
        db.query(RefreshToken).filter(
            RefreshToken.username == stored_token.username
        ).update({"is_revoked": True})
        db.commit()
        log_security_event("Token Replay Attack", f"Revoked refresh token reused for user {stored_token.username}", client_ip)

        # Sync revocation to all peers
        tokens = db.query(RefreshToken).filter(RefreshToken.username == stored_token.username).all()
        for t in tokens:
            _sync_event("UPDATE", "refresh_tokens", {
                "token_hash": t.token_hash,
                "username": t.username,
                "expires_at": t.expires_at,
                "is_revoked": True,
                "created_at": t.created_at,
            }, db)

        raise HTTPException(status_code=401, detail="Refresh token has been revoked. All sessions invalidated.")

    if stored_token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token has expired. Please log in again.")

    # Revoke the old refresh token (one-time use)
    stored_token.is_revoked = True
    db.commit()

    # Sync revocation to peers
    _sync_event("UPDATE", "refresh_tokens", {
        "token_hash": stored_token.token_hash,
        "username": stored_token.username,
        "expires_at": stored_token.expires_at,
        "is_revoked": True,
        "created_at": stored_token.created_at,
    }, db)

    # Get the user
    user = db.query(User).filter(User.username == stored_token.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Issue new tokens
    new_access_token = create_access_token(data={"sub": user.username, "role": user.role})
    new_refresh_token = create_refresh_token(user.username, db)

    log_token_refresh(user.username, client_ip)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

# ============================================================
# Routes: User Profile
# ============================================================

@app.get("/users/me")
def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user.get("sub"), "role": current_user.get("role")}

# ============================================================
# Routes: Encrypted File Storage
# ============================================================

@app.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    storage_node: str = Form(default=None),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload a file. The file content is encrypted with AES-256-GCM before storage.
    Files are stored on this node's local database (not synced to peers).
    """
    if not key_manager:
        raise HTTPException(status_code=503, detail="Encryption service not available. MASTER_ENCRYPTION_KEY not configured.")

    username = current_user.get("sub")

    # Check access restrictions
    node = storage_node or get_storage_node()
    restriction = check_access_restriction(username, node, None, db)
    if restriction["blocked"]:
        raise HTTPException(status_code=403, detail=restriction["reason"])

    # Read file content
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum size is {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.")

    # Encrypt the file content
    key_id, dek = key_manager.get_active_key(node, db)
    encrypted_content = encrypt_data(content, dek)

    # Store encrypted file (node-local, NOT synced)
    encrypted_file = EncryptedFile(
        filename=file.filename,
        owner_username=username,
        encrypted_content=encrypted_content,
        encryption_key_id=key_id,
        storage_node=node,
        file_size_bytes=len(content),
    )
    db.add(encrypted_file)
    db.commit()
    db.refresh(encrypted_file)

    log_file_encryption(file.filename, node, key_id, "ENCRYPT")

    return {
        "id": encrypted_file.id,
        "filename": encrypted_file.filename,
        "storage_node": node,
        "encryption_key_id": key_id,
        "file_size_bytes": len(content),
        "encrypted_size_bytes": len(encrypted_content),
        "message": "File uploaded and encrypted successfully",
    }

@app.get("/files/")
def list_files(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all files owned by the current user on THIS node."""
    username = current_user.get("sub")
    files = db.query(EncryptedFile).filter(EncryptedFile.owner_username == username).all()

    return {
        "files": [
            {
                "id": f.id,
                "filename": f.filename,
                "storage_node": f.storage_node,
                "encryption_key_id": f.encryption_key_id,
                "file_size_bytes": f.file_size_bytes,
                "created_at": str(f.created_at),
                "updated_at": str(f.updated_at),
            }
            for f in files
        ],
        "total": len(files),
        "node": NODE_ID,
    }

@app.get("/files/{file_id}")
def download_file(file_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Download and decrypt a file from this node."""
    if not key_manager:
        raise HTTPException(status_code=503, detail="Encryption service not available.")

    username = current_user.get("sub")
    role = current_user.get("role")

    encrypted_file = db.query(EncryptedFile).filter(EncryptedFile.id == file_id).first()
    if not encrypted_file:
        raise HTTPException(status_code=404, detail="File not found on this node")

    # Only owner or admin can download
    if encrypted_file.owner_username != username and role != "admin":
        raise HTTPException(status_code=403, detail="You don't have permission to access this file")

    # Check access restrictions
    restriction = check_access_restriction(username, encrypted_file.storage_node, file_id, db)
    if restriction["blocked"]:
        raise HTTPException(status_code=403, detail=restriction["reason"])

    # Decrypt the file content
    try:
        key_id, dek = key_manager.get_active_key(encrypted_file.storage_node, db)

        # If the file was encrypted with a different key (before rotation),
        # we need to find that specific key
        if encrypted_file.encryption_key_id != key_id:
            old_key_record = db.query(EncryptionKey).filter(
                EncryptionKey.key_id == encrypted_file.encryption_key_id
            ).first()
            if old_key_record and old_key_record.wrapped_key:
                from security_modules.key_manager import unwrap_key, get_master_key
                dek = unwrap_key(old_key_record.wrapped_key, get_master_key())
            else:
                raise HTTPException(status_code=500, detail="Encryption key not found for this file")

        decrypted_content = decrypt_data(encrypted_file.encrypted_content, dek)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt file: {str(e)}")

    log_file_encryption(encrypted_file.filename, encrypted_file.storage_node, encrypted_file.encryption_key_id, "DECRYPT")

    return Response(
        content=decrypted_content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{encrypted_file.filename}"'}
    )

@app.delete("/files/{file_id}")
def delete_file(file_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Delete an encrypted file from this node."""
    username = current_user.get("sub")
    role = current_user.get("role")

    encrypted_file = db.query(EncryptedFile).filter(EncryptedFile.id == file_id).first()
    if not encrypted_file:
        raise HTTPException(status_code=404, detail="File not found")

    if encrypted_file.owner_username != username and role != "admin":
        raise HTTPException(status_code=403, detail="You don't have permission to delete this file")

    db.delete(encrypted_file)
    db.commit()

    return {"message": f"File '{encrypted_file.filename}' deleted successfully"}

# ============================================================
# Routes: Admin Dashboard & Security Management
# ============================================================

@app.get("/admin/dashboard", dependencies=[Depends(RoleChecker("admin"))])
def admin_dashboard(db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_files = db.query(EncryptedFile).count()
    active_alerts = db.query(SecurityAlert).filter(SecurityAlert.resolved == False).count()
    active_restrictions = db.query(AccessRestriction).filter(
        AccessRestriction.restricted_until > datetime.utcnow()
    ).count()
    active_keys = db.query(EncryptionKey).filter(EncryptionKey.is_active == True).count()

    return {
        "message": "Welcome to the admin dashboard",
        "system_status": "All systems operational",
        "active_users": total_users,
        "total_encrypted_files": total_files,
        "active_security_alerts": active_alerts,
        "active_access_restrictions": active_restrictions,
        "active_encryption_keys": active_keys,
        "node": NODE_ID,
        "peers": PEER_NODES,
    }

@app.get("/admin/alerts", dependencies=[Depends(RoleChecker("admin"))])
def list_alerts(resolved: bool = None, severity: str = None, db: Session = Depends(get_db)):
    """View security alerts with optional filtering."""
    query = db.query(SecurityAlert)
    if resolved is not None:
        query = query.filter(SecurityAlert.resolved == resolved)
    if severity:
        query = query.filter(SecurityAlert.severity == severity.upper())

    alerts = query.order_by(SecurityAlert.created_at.desc()).limit(100).all()

    return {
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
                "source_ip": a.source_ip,
                "username": a.username,
                "resolved": a.resolved,
                "created_at": str(a.created_at),
            }
            for a in alerts
        ],
        "total": len(alerts),
    }

@app.put("/admin/alerts/{alert_id}/resolve", dependencies=[Depends(RoleChecker("admin"))])
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark a security alert as resolved."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    db.commit()

    # Sync alert resolution to peers
    _sync_event("UPDATE", "security_alerts", {
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "description": alert.description,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "resolved": True,
        "created_at": alert.created_at,
    }, db)

    return {"message": f"Alert {alert_id} marked as resolved"}

@app.get("/admin/restrictions", dependencies=[Depends(RoleChecker("admin"))])
def list_restrictions(db: Session = Depends(get_db)):
    """View active access restrictions."""
    restrictions = db.query(AccessRestriction).filter(
        AccessRestriction.restricted_until > datetime.utcnow()
    ).all()

    return {
        "restrictions": [
            {
                "id": r.id,
                "username": r.username,
                "restriction_type": r.restriction_type,
                "target": r.target,
                "reason": r.reason,
                "restricted_until": str(r.restricted_until),
                "created_at": str(r.created_at),
            }
            for r in restrictions
        ],
        "total": len(restrictions),
    }

@app.delete("/admin/restrictions/{restriction_id}", dependencies=[Depends(RoleChecker("admin"))])
def lift_restriction(restriction_id: int, db: Session = Depends(get_db)):
    """Manually lift an access restriction."""
    restriction = db.query(AccessRestriction).filter(AccessRestriction.id == restriction_id).first()
    if not restriction:
        raise HTTPException(status_code=404, detail="Restriction not found")

    # Sync deletion to peers
    _sync_event("DELETE", "access_restrictions", {
        "username": restriction.username,
        "restriction_type": restriction.restriction_type,
        "target": restriction.target,
    }, db)

    db.delete(restriction)
    db.commit()
    return {"message": f"Restriction {restriction_id} lifted"}

@app.get("/admin/security/status", dependencies=[Depends(RoleChecker("admin"))])
def security_status(db: Session = Depends(get_db)):
    """Security dashboard with system-wide statistics."""
    now = datetime.utcnow()
    one_hour_ago = now - timedelta(hours=1)
    one_day_ago = now - timedelta(days=1)

    # Count sync statistics
    total_sync_events = db.query(SyncEvent).count()
    pending_sync = db.query(SyncRetryQueue).filter(SyncRetryQueue.retry_count < 10).count()
    failed_sync = db.query(SyncRetryQueue).filter(SyncRetryQueue.retry_count >= 10).count()

    return {
        "encryption": {
            "total_encrypted_files": db.query(EncryptedFile).count(),
            "active_encryption_keys": db.query(EncryptionKey).filter(EncryptionKey.is_active == True).count(),
            "key_manager_active": key_manager is not None,
        },
        "access_control": {
            "active_restrictions": db.query(AccessRestriction).filter(
                AccessRestriction.restricted_until > now
            ).count(),
            "blocked_ips": db.query(IPBlacklist).filter(
                IPBlacklist.blocked_until > now
            ).count(),
            "locked_accounts": db.query(User).filter(
                User.locked_until > now
            ).count(),
        },
        "alerts": {
            "unresolved_total": db.query(SecurityAlert).filter(SecurityAlert.resolved == False).count(),
            "critical_unresolved": db.query(SecurityAlert).filter(
                SecurityAlert.resolved == False, SecurityAlert.severity == "HIGH"
            ).count(),
            "alerts_last_hour": db.query(SecurityAlert).filter(
                SecurityAlert.created_at >= one_hour_ago
            ).count(),
        },
        "access_logs": {
            "requests_last_hour": db.query(AccessLog).filter(
                AccessLog.timestamp >= one_hour_ago
            ).count(),
            "requests_last_24h": db.query(AccessLog).filter(
                AccessLog.timestamp >= one_day_ago
            ).count(),
            "failed_logins_last_hour": db.query(AccessLog).filter(
                AccessLog.timestamp >= one_hour_ago,
                AccessLog.endpoint.like("%/auth/login%"),
                AccessLog.status_code.in_([400, 401, 403])
            ).count(),
        },
        "tokens": {
            "active_refresh_tokens": db.query(RefreshToken).filter(
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > now
            ).count(),
        },
        "distributed_sync": {
            "total_sync_events": total_sync_events,
            "pending_sync_items": pending_sync,
            "failed_sync_items": failed_sync,
            "peer_nodes": PEER_NODES,
        },
        "node": NODE_ID,
        "timestamp": str(now),
    }

@app.post("/admin/keys/rotate/{node_id}", dependencies=[Depends(RoleChecker("admin"))])
def manual_key_rotation(node_id: str, db: Session = Depends(get_db)):
    """Manually trigger key rotation for a specific node."""
    if not key_manager:
        raise HTTPException(status_code=503, detail="Key Manager not available.")

    result = key_manager.rotate_key(node_id, db)

    from security_modules.monitoring.logger import log_key_rotation
    log_key_rotation(result["new_key_id"], node_id, result["files_re_encrypted"])

    # Sync the new key to all peers so they can decrypt files from this node
    new_key_record = db.query(EncryptionKey).filter(
        EncryptionKey.key_id == result["new_key_id"]
    ).first()
    if new_key_record:
        _sync_event("INSERT", "encryption_keys", {
            "key_id": new_key_record.key_id,
            "key_purpose": new_key_record.key_purpose,
            "wrapped_key": new_key_record.wrapped_key,
            "is_active": new_key_record.is_active,
            "node_id": new_key_record.node_id,
            "created_at": new_key_record.created_at,
            "rotated_at": new_key_record.rotated_at,
        }, db)

    # Also sync the deactivation of the old key
    if result["old_key_id"]:
        old_key_record = db.query(EncryptionKey).filter(
            EncryptionKey.key_id == result["old_key_id"]
        ).first()
        if old_key_record:
            _sync_event("UPDATE", "encryption_keys", {
                "key_id": old_key_record.key_id,
                "key_purpose": old_key_record.key_purpose,
                "wrapped_key": old_key_record.wrapped_key,
                "is_active": old_key_record.is_active,
                "node_id": old_key_record.node_id,
                "created_at": old_key_record.created_at,
                "rotated_at": old_key_record.rotated_at,
            }, db)

    return {
        "message": f"Key rotation completed for node '{node_id}'",
        "old_key_id": result["old_key_id"],
        "new_key_id": result["new_key_id"],
        "files_re_encrypted": result["files_re_encrypted"],
        "synced_to_peers": PEER_NODES,
    }

# ============================================================
# Routes: Cluster Management (Admin)
# ============================================================

@app.get("/admin/cluster/status", dependencies=[Depends(RoleChecker("admin"))])
async def cluster_status(db: Session = Depends(get_db)):
    """View the health and sync status of all nodes in the cluster."""
    import httpx as httpx_lib

    node_statuses = []

    # This node
    node_statuses.append({
        "node": NODE_ID,
        "status": "healthy",
        "is_self": True,
        "sync_events": db.query(SyncEvent).count(),
        "pending_sync": db.query(SyncRetryQueue).filter(SyncRetryQueue.retry_count < 10).count(),
    })

    # Check peers
    for peer_url in PEER_NODES:
        try:
            async with httpx_lib.AsyncClient(verify=False, timeout=5.0) as client:
                response = await client.get(f"{peer_url}/internal/health")
            if response.status_code == 200:
                data = response.json()
                node_statuses.append({
                    "node": data.get("node", peer_url),
                    "url": peer_url,
                    "status": "healthy",
                    "is_self": False,
                })
            else:
                node_statuses.append({
                    "node": peer_url,
                    "url": peer_url,
                    "status": f"error ({response.status_code})",
                    "is_self": False,
                })
        except Exception as e:
            node_statuses.append({
                "node": peer_url,
                "url": peer_url,
                "status": "unreachable",
                "is_self": False,
                "error": str(e),
            })

    healthy = sum(1 for n in node_statuses if n["status"] == "healthy")
    total = len(node_statuses)

    return {
        "cluster_health": f"{healthy}/{total} nodes healthy",
        "nodes": node_statuses,
    }
