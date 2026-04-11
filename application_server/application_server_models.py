"""
SQLAlchemy models for the application.

Separated from main.py to allow import by security modules without circular dependencies.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, LargeBinary, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="user")
    created_at = Column(DateTime, default=datetime.utcnow)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)


class IPBlacklist(Base):
    __tablename__ = "ip_blacklist"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    failed_attempts = Column(Integer, default=1)
    blocked_until = Column(DateTime, nullable=True)
    last_attempt = Column(DateTime, default=datetime.utcnow)


class EncryptedFile(Base):
    __tablename__ = "encrypted_files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    owner_username = Column(String(50), nullable=False)
    encrypted_content = Column(LargeBinary, nullable=False)
    encryption_key_id = Column(String(100), nullable=False)
    storage_node = Column(String(50), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class EncryptionKey(Base):
    __tablename__ = "encryption_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_id = Column(String(100), unique=True, nullable=False)
    key_purpose = Column(String(50), nullable=False, default="data")
    wrapped_key = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    rotated_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    node_id = Column(String(50), nullable=True)


class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=True)
    ip_address = Column(String(45), nullable=True)
    endpoint = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)
    status_code = Column(Integer, nullable=True)
    storage_node = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    source_ip = Column(String(45), nullable=True)
    username = Column(String(50), nullable=True)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AccessRestriction(Base):
    __tablename__ = "access_restrictions"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False)
    restriction_type = Column(String(50), nullable=False)
    target = Column(String(255), nullable=True)
    reason = Column(Text, nullable=True)
    restricted_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(255), unique=True, nullable=False)
    username = Column(String(50), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ===== Distributed Synchronization Models =====

class SyncEvent(Base):
    __tablename__ = "sync_events"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(100), unique=True, nullable=False)
    event_type = Column(String(50), nullable=False)
    table_name = Column(String(100), nullable=False)
    payload = Column(Text, nullable=False)  # JSON string
    source_node = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    applied = Column(Boolean, default=True)


class SyncRetryQueue(Base):
    __tablename__ = "sync_retry_queue"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(100), nullable=False)
    target_node = Column(String(255), nullable=False)
    retry_count = Column(Integer, default=0)
    last_attempt = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
