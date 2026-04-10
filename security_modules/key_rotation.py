"""
Key Rotation and Token Renewal Module.

Implements periodic security maintenance tasks:
1. Key Rotation: Automatically rotates per-node encryption keys at configurable intervals.
   Re-encrypts all affected files with the new key transparently.
2. Token Renewal: Short-lived access tokens (15 min) + long-lived refresh tokens (7 days)
   with one-time-use rotation to prevent replay attacks.
3. Restriction Cleanup: Periodically lifts expired access restrictions.
"""

import asyncio
import os
from datetime import datetime


async def run_key_rotation_scheduler(key_manager, db_session_factory,
                                     interval_hours: int = None):
    """
    Periodically rotate encryption keys for all storage nodes.

    Args:
        key_manager: KeyManager instance.
        db_session_factory: SQLAlchemy sessionmaker.
        interval_hours: Hours between rotations (from env or default 24).
    """
    if interval_hours is None:
        interval_hours = int(os.getenv("KEY_ROTATION_INTERVAL_HOURS", "24"))

    interval_seconds = interval_hours * 3600

    # Wait before first rotation (let system stabilize)
    await asyncio.sleep(30)

    while True:
        try:
            db = db_session_factory()
            try:
                node_ids = _get_active_node_ids(db)

                for node_id in node_ids:
                    try:
                        result = key_manager.rotate_key(node_id, db)

                        from security_modules.monitoring.logger import log_key_rotation
                        log_key_rotation(
                            result["new_key_id"],
                            node_id,
                            result["files_re_encrypted"]
                        )
                        print(f"[Key Rotation] Node '{node_id}': rotated key "
                              f"{result['old_key_id']} -> {result['new_key_id']}, "
                              f"re-encrypted {result['files_re_encrypted']} files.")
                    except Exception as e:
                        print(f"[Key Rotation] Error rotating key for node '{node_id}': {e}")

                # Clear key cache after rotation
                key_manager.clear_cache()

            finally:
                db.close()
        except Exception as e:
            print(f"[Key Rotation Scheduler] Error: {e}")

        await asyncio.sleep(interval_seconds)


async def run_restriction_cleanup(db_session_factory, interval_seconds: int = 300):
    """
    Periodically clean up expired access restrictions.

    Args:
        db_session_factory: SQLAlchemy sessionmaker.
        interval_seconds: How often to run cleanup (default 5 min).
    """
    while True:
        try:
            db = db_session_factory()
            try:
                from security_modules.access_control import lift_expired_restrictions
                count = lift_expired_restrictions(db)
                if count > 0:
                    print(f"[Restriction Cleanup] Removed {count} expired restrictions.")
            finally:
                db.close()
        except Exception as e:
            print(f"[Restriction Cleanup] Error: {e}")

        await asyncio.sleep(interval_seconds)


def _get_active_node_ids(db) -> list:
    """Get all storage node IDs that have active encryption keys or stored files."""
    from application_server_models import EncryptionKey, EncryptedFile

    # Get nodes from encryption keys
    key_nodes = db.query(EncryptionKey.node_id).filter(
        EncryptionKey.node_id.isnot(None)
    ).distinct().all()

    # Get nodes from stored files
    file_nodes = db.query(EncryptedFile.storage_node).distinct().all()

    all_nodes = set()
    for (node_id,) in key_nodes:
        if node_id:
            all_nodes.add(node_id)
    for (node_id,) in file_nodes:
        if node_id:
            all_nodes.add(node_id)

    # Include default node IDs if no nodes are found
    if not all_nodes:
        all_nodes = {"node_1", "node_2", "node_3"}

    return list(all_nodes)
