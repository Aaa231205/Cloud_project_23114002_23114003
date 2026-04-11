"""
Distributed Synchronization Manager.

Implements gossip-style data replication across distributed storage nodes.
Each node maintains its own database and pushes changes to all known peers
via HTTPS (TLS-encrypted) to ensure data confidentiality in transit.

Sync Protocol:
1. Node makes a local write (e.g., user registration, key rotation)
2. Node records a SyncEvent with a unique event_id (UUID)
3. Node pushes the event to all peer nodes via HTTPS POST
4. Peers apply the event idempotently (skip if event_id already exists)
5. If a peer is unreachable, the event goes into a retry queue
6. A background task periodically retries failed syncs
7. On startup, a node requests catch-up sync from peers for missed events

Consistency Model: Eventual consistency
Fault Tolerance: Retry queue + catch-up sync on recovery
"""

import os
import json
import uuid
import asyncio
import ssl
from datetime import datetime, timedelta
from typing import List, Optional

# Use httpx for async HTTPS requests (added to requirements.txt)
try:
    import httpx
except ImportError:
    httpx = None
    print("[Sync Manager] Warning: httpx not installed. Sync disabled.")


class SyncManager:
    """
    Manages cross-node data synchronization using gossip-style push replication.
    All inter-node communication uses HTTPS for encryption in transit.
    """

    def __init__(self, node_id: str, peer_nodes: List[str], db_session_factory):
        """
        Args:
            node_id: This node's unique identifier (e.g., 'node_1').
            peer_nodes: List of peer node HTTPS URLs (e.g., ['https://app_server_2:8443']).
            db_session_factory: SQLAlchemy sessionmaker.
        """
        self.node_id = node_id
        self.peer_nodes = [p.strip() for p in peer_nodes if p.strip()]
        self.db_session_factory = db_session_factory
        self._ssl_context = self._create_ssl_context()

        print(f"[Sync Manager] Node '{node_id}' initialized with peers: {self.peer_nodes}")

    def _create_ssl_context(self):
        """Create an SSL context that accepts self-signed certificates for internal sync."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Self-signed certs in internal network
        return ctx

    def create_event(self, event_type: str, table_name: str, data: dict, db) -> str:
        """
        Record a sync event locally and push it to all peers.

        Args:
            event_type: 'INSERT', 'UPDATE', or 'DELETE'.
            table_name: The table being modified.
            data: The row data as a dict (must be JSON-serializable).
            db: Active database session.

        Returns:
            The unique event_id.
        """
        from application_server_models import SyncEvent

        event_id = f"{self.node_id}_{uuid.uuid4().hex[:16]}"

        # Sanitize data for JSON serialization
        sanitized = _sanitize_for_json(data)

        sync_event = SyncEvent(
            event_id=event_id,
            event_type=event_type,
            table_name=table_name,
            payload=json.dumps(sanitized),
            source_node=self.node_id,
            applied=True,
        )
        db.add(sync_event)
        db.commit()

        # Schedule async push to peers (fire-and-forget from sync context)
        # The actual push happens via the background retry loop or explicit call
        self._queue_for_peers(event_id, db)

        return event_id

    def _queue_for_peers(self, event_id: str, db):
        """Add retry queue entries for all peers."""
        from application_server_models import SyncRetryQueue

        for peer in self.peer_nodes:
            retry = SyncRetryQueue(
                event_id=event_id,
                target_node=peer,
                retry_count=0,
            )
            db.add(retry)
        db.commit()

    def apply_remote_event(self, event_data: dict, db) -> dict:
        """
        Apply a sync event received from a remote peer.
        Idempotent: skips if the event_id already exists locally.

        Args:
            event_data: Dict with event_id, event_type, table_name, payload, source_node.
            db: Active database session.

        Returns:
            Dict with 'status' ('applied', 'skipped', or 'error').
        """
        from application_server_models import SyncEvent

        event_id = event_data.get("event_id")
        if not event_id:
            return {"status": "error", "detail": "Missing event_id"}

        # Check idempotency — skip if already applied
        existing = db.query(SyncEvent).filter(SyncEvent.event_id == event_id).first()
        if existing:
            return {"status": "skipped", "detail": f"Event {event_id} already applied"}

        # Record the event — ensure payload is stored as a JSON string
        raw_payload = event_data.get("payload", "{}")
        if isinstance(raw_payload, dict):
            raw_payload = json.dumps(raw_payload)

        sync_event = SyncEvent(
            event_id=event_id,
            event_type=event_data.get("event_type", "INSERT"),
            table_name=event_data.get("table_name", ""),
            payload=raw_payload,
            source_node=event_data.get("source_node", "unknown"),
            applied=False,
        )
        db.add(sync_event)

        # Apply the actual data change
        try:
            table_name = event_data.get("table_name")
            event_type = event_data.get("event_type")
            payload = event_data.get("payload", "{}")
            if isinstance(payload, str):
                payload = json.loads(payload)

            self._apply_data_change(table_name, event_type, payload, db)
            sync_event.applied = True
            db.commit()

            return {"status": "applied", "detail": f"Event {event_id} applied successfully"}

        except Exception as e:
            db.rollback()
            return {"status": "error", "detail": f"Failed to apply event {event_id}: {str(e)}"}

    def _apply_data_change(self, table_name: str, event_type: str, payload: dict, db):
        """
        Apply a data change to the local database based on the table and operation type.
        This is the core replication logic.
        """
        from application_server_models import (
            User, IPBlacklist, EncryptionKey,
            SecurityAlert, AccessRestriction, RefreshToken
        )

        table_map = {
            "users": User,
            "ip_blacklist": IPBlacklist,
            "encryption_keys": EncryptionKey,
            "security_alerts": SecurityAlert,
            "access_restrictions": AccessRestriction,
            "refresh_tokens": RefreshToken,
        }

        model_class = table_map.get(table_name)
        if not model_class:
            print(f"[Sync] Unknown table '{table_name}', skipping.")
            return

        if event_type == "INSERT":
            self._apply_insert(model_class, table_name, payload, db)
        elif event_type == "UPDATE":
            self._apply_update(model_class, table_name, payload, db)
        elif event_type == "DELETE":
            self._apply_delete(model_class, table_name, payload, db)

    def _apply_insert(self, model_class, table_name, payload, db):
        """Insert a new row, skipping if it already exists (by unique key)."""
        # Check for existing record by unique identifier
        unique_check = self._find_existing(model_class, table_name, payload, db)
        if unique_check:
            # Update existing record instead of inserting
            self._apply_update(model_class, table_name, payload, db)
            return

        # Remove 'id' to let the local DB auto-generate
        clean_payload = {k: v for k, v in payload.items() if k != "id"}

        # Convert datetime strings
        clean_payload = _restore_datetimes(clean_payload)

        record = model_class(**clean_payload)
        db.add(record)
        db.flush()

    def _apply_update(self, model_class, table_name, payload, db):
        """Update an existing row by its unique identifier."""
        existing = self._find_existing(model_class, table_name, payload, db)
        if not existing:
            # Record doesn't exist locally; do an insert instead
            self._apply_insert(model_class, table_name, payload, db)
            return

        clean_payload = _restore_datetimes(payload)
        for key, value in clean_payload.items():
            if key != "id" and hasattr(existing, key):
                setattr(existing, key, value)
        db.flush()

    def _apply_delete(self, model_class, table_name, payload, db):
        """Delete a row by its unique identifier."""
        existing = self._find_existing(model_class, table_name, payload, db)
        if existing:
            db.delete(existing)
            db.flush()

    def _find_existing(self, model_class, table_name, payload, db):
        """Find an existing record by the table's natural unique key."""
        if table_name == "users":
            return db.query(model_class).filter(
                model_class.username == payload.get("username")
            ).first()
        elif table_name == "ip_blacklist":
            return db.query(model_class).filter(
                model_class.ip_address == payload.get("ip_address")
            ).first()
        elif table_name == "encryption_keys":
            return db.query(model_class).filter(
                model_class.key_id == payload.get("key_id")
            ).first()
        elif table_name == "security_alerts":
            # Alerts use a composite check to avoid duplicates
            return db.query(model_class).filter(
                model_class.alert_type == payload.get("alert_type"),
                model_class.username == payload.get("username"),
                model_class.source_ip == payload.get("source_ip"),
                model_class.description == payload.get("description"),
            ).first()
        elif table_name == "access_restrictions":
            return db.query(model_class).filter(
                model_class.username == payload.get("username"),
                model_class.restriction_type == payload.get("restriction_type"),
                model_class.target == payload.get("target"),
            ).first()
        elif table_name == "refresh_tokens":
            return db.query(model_class).filter(
                model_class.token_hash == payload.get("token_hash")
            ).first()
        return None

    def get_events_since(self, since_timestamp: str, db) -> list:
        """
        Get all sync events created after the given timestamp.
        Used for catch-up sync when a node recovers.

        Args:
            since_timestamp: ISO format timestamp string.
            db: Active database session.

        Returns:
            List of event dicts.
        """
        from application_server_models import SyncEvent

        try:
            ts = datetime.fromisoformat(since_timestamp)
        except (ValueError, TypeError):
            ts = datetime.utcnow() - timedelta(hours=24)  # Default: last 24h

        events = db.query(SyncEvent).filter(
            SyncEvent.created_at >= ts,
            SyncEvent.source_node == self.node_id  # Only send our own events
        ).order_by(SyncEvent.created_at.asc()).all()

        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "table_name": e.table_name,
                "payload": e.payload,
                "source_node": e.source_node,
                "created_at": str(e.created_at),
            }
            for e in events
        ]

    def get_full_sync_data(self, db) -> dict:
        """
        Export all syncable data for a full catch-up sync.
        Used when a node has been down for a long time.

        Returns:
            Dict with table_name -> list of row dicts.
        """
        from application_server_models import (
            User, IPBlacklist, EncryptionKey,
            SecurityAlert, AccessRestriction, RefreshToken
        )

        result = {}

        # Users
        users = db.query(User).all()
        result["users"] = [
            {
                "username": u.username, "password_hash": u.password_hash,
                "role": u.role, "created_at": str(u.created_at),
                "failed_login_attempts": u.failed_login_attempts,
                "locked_until": str(u.locked_until) if u.locked_until else None,
            }
            for u in users
        ]

        # IP Blacklist
        ips = db.query(IPBlacklist).all()
        result["ip_blacklist"] = [
            {
                "ip_address": ip.ip_address, "failed_attempts": ip.failed_attempts,
                "blocked_until": str(ip.blocked_until) if ip.blocked_until else None,
                "last_attempt": str(ip.last_attempt) if ip.last_attempt else None,
            }
            for ip in ips
        ]

        # Encryption Keys
        keys = db.query(EncryptionKey).all()
        result["encryption_keys"] = [
            {
                "key_id": k.key_id, "key_purpose": k.key_purpose,
                "wrapped_key": k.wrapped_key, "is_active": k.is_active,
                "node_id": k.node_id,
                "created_at": str(k.created_at),
                "rotated_at": str(k.rotated_at) if k.rotated_at else None,
            }
            for k in keys
        ]

        # Security Alerts
        alerts = db.query(SecurityAlert).all()
        result["security_alerts"] = [
            {
                "alert_type": a.alert_type, "severity": a.severity,
                "description": a.description, "source_ip": a.source_ip,
                "username": a.username, "resolved": a.resolved,
                "created_at": str(a.created_at),
            }
            for a in alerts
        ]

        # Access Restrictions
        restrictions = db.query(AccessRestriction).all()
        result["access_restrictions"] = [
            {
                "username": r.username, "restriction_type": r.restriction_type,
                "target": r.target, "reason": r.reason,
                "restricted_until": str(r.restricted_until) if r.restricted_until else None,
                "created_at": str(r.created_at),
            }
            for r in restrictions
        ]

        # Refresh Tokens
        tokens = db.query(RefreshToken).all()
        result["refresh_tokens"] = [
            {
                "token_hash": t.token_hash, "username": t.username,
                "expires_at": str(t.expires_at), "is_revoked": t.is_revoked,
                "created_at": str(t.created_at),
            }
            for t in tokens
        ]

        return result

    def apply_full_sync(self, data: dict, db):
        """
        Apply a full sync data dump from a peer. Used for catch-up after downtime.
        Merges data — inserts missing records, updates existing ones.

        Args:
            data: Dict from get_full_sync_data().
            db: Active database session.
        """
        from application_server_models import (
            User, IPBlacklist, EncryptionKey,
            SecurityAlert, AccessRestriction, RefreshToken
        )

        table_map = {
            "users": User,
            "ip_blacklist": IPBlacklist,
            "encryption_keys": EncryptionKey,
            "security_alerts": SecurityAlert,
            "access_restrictions": AccessRestriction,
            "refresh_tokens": RefreshToken,
        }

        total_applied = 0
        for table_name, rows in data.items():
            model_class = table_map.get(table_name)
            if not model_class or not rows:
                continue

            for row in rows:
                try:
                    existing = self._find_existing(model_class, table_name, row, db)
                    clean = _restore_datetimes(row)
                    if existing:
                        for key, value in clean.items():
                            if key != "id" and hasattr(existing, key):
                                setattr(existing, key, value)
                    else:
                        record = model_class(**clean)
                        db.add(record)
                    total_applied += 1
                except Exception as e:
                    print(f"[Sync] Error applying {table_name} row: {e}")

        db.commit()
        print(f"[Sync] Full sync applied: {total_applied} records merged.")


async def run_sync_push_loop(sync_manager, db_session_factory, interval_seconds: int = 5):
    """
    Background task that processes the sync retry queue.
    Pushes pending events to peers via HTTPS.

    Args:
        sync_manager: SyncManager instance.
        db_session_factory: SQLAlchemy sessionmaker.
        interval_seconds: How often to process the queue.
    """
    if not httpx:
        print("[Sync Push] httpx not available. Sync push disabled.")
        return

    # Wait for system to stabilize
    await asyncio.sleep(10)

    while True:
        try:
            db = db_session_factory()
            try:
                from application_server_models import SyncRetryQueue, SyncEvent

                # Get pending items (max 50 per cycle)
                pending = db.query(SyncRetryQueue).filter(
                    SyncRetryQueue.retry_count < 10  # Give up after 10 retries
                ).order_by(SyncRetryQueue.created_at.asc()).limit(50).all()

                if not pending:
                    await asyncio.sleep(interval_seconds)
                    continue

                # Group by target node
                by_target = {}
                for item in pending:
                    by_target.setdefault(item.target_node, []).append(item)

                for target_url, items in by_target.items():
                    # Gather the events
                    event_ids = [i.event_id for i in items]
                    events = db.query(SyncEvent).filter(
                        SyncEvent.event_id.in_(event_ids)
                    ).all()

                    event_data_list = [
                        {
                            "event_id": e.event_id,
                            "event_type": e.event_type,
                            "table_name": e.table_name,
                            "payload": e.payload,
                            "source_node": e.source_node,
                            "created_at": str(e.created_at),
                        }
                        for e in events
                    ]

                    if not event_data_list:
                        # Events were already cleaned up; remove queue entries
                        for item in items:
                            db.delete(item)
                        db.commit()
                        continue

                    # Push to peer via HTTPS
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                            response = await client.post(
                                f"{target_url}/internal/sync/push",
                                json={"events": event_data_list},
                            )

                        if response.status_code == 200:
                            # Success — remove from retry queue
                            for item in items:
                                db.delete(item)
                            db.commit()
                        else:
                            # Server error — increment retry count
                            for item in items:
                                item.retry_count += 1
                                item.last_attempt = datetime.utcnow()
                            db.commit()

                    except Exception as e:
                        # Connection error — increment retry count
                        for item in items:
                            item.retry_count += 1
                            item.last_attempt = datetime.utcnow()
                        db.commit()
                        print(f"[Sync Push] Failed to reach {target_url}: {e}")

            finally:
                db.close()

        except Exception as e:
            print(f"[Sync Push Loop] Error: {e}")

        await asyncio.sleep(interval_seconds)


async def run_catch_up_sync(sync_manager, db_session_factory):
    """
    On startup, request a full sync from the first available peer.
    This ensures a node that was down catches up on missed events.

    Args:
        sync_manager: SyncManager instance.
        db_session_factory: SQLAlchemy sessionmaker.
    """
    if not httpx or not sync_manager.peer_nodes:
        print("[Catch-up Sync] No peers or httpx not available. Skipping.")
        return

    # Wait for peers to be ready
    await asyncio.sleep(15)

    for peer_url in sync_manager.peer_nodes:
        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.get(f"{peer_url}/internal/sync/full")

            if response.status_code == 200:
                data = response.json()
                db = db_session_factory()
                try:
                    sync_manager.apply_full_sync(data, db)
                    print(f"[Catch-up Sync] Successfully synced from {peer_url}")
                    return  # Success — no need to try other peers
                finally:
                    db.close()
            else:
                print(f"[Catch-up Sync] Peer {peer_url} returned {response.status_code}")

        except Exception as e:
            print(f"[Catch-up Sync] Peer {peer_url} unreachable: {e}")

    print("[Catch-up Sync] No peers available for catch-up. Starting with local data only.")


async def run_peer_health_check(sync_manager, interval_seconds: int = 30):
    """
    Periodically check if peer nodes are alive.
    Logs the health status of each peer.

    Args:
        sync_manager: SyncManager instance.
        interval_seconds: How often to check.
    """
    if not httpx or not sync_manager.peer_nodes:
        return

    await asyncio.sleep(20)

    while True:
        for peer_url in sync_manager.peer_nodes:
            try:
                async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                    response = await client.get(f"{peer_url}/internal/health")
                if response.status_code == 200:
                    pass  # Peer is healthy — silent
                else:
                    print(f"[Health Check] Peer {peer_url} returned {response.status_code}")
            except Exception:
                print(f"[Health Check] Peer {peer_url} is UNREACHABLE")

        await asyncio.sleep(interval_seconds)


# ============================================================
# Utility Functions
# ============================================================

def _sanitize_for_json(data: dict) -> dict:
    """Convert non-JSON-serializable types (datetime, bytes) to strings."""
    result = {}
    for key, value in data.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, bytes):
            import base64
            result[key] = base64.b64encode(value).decode("utf-8")
        elif value is None:
            result[key] = None
        else:
            result[key] = value
    return result


def _restore_datetimes(data: dict) -> dict:
    """Convert ISO datetime strings back to datetime objects for known fields."""
    datetime_fields = {
        "created_at", "updated_at", "locked_until", "blocked_until",
        "last_attempt", "rotated_at", "restricted_until", "expires_at",
    }
    result = {}
    for key, value in data.items():
        if key in datetime_fields and isinstance(value, str) and value != "None":
            try:
                result[key] = datetime.fromisoformat(value)
            except (ValueError, TypeError):
                result[key] = None
        elif key in datetime_fields and (value is None or value == "None"):
            result[key] = None
        else:
            result[key] = value
    return result
