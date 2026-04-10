"""
Secure Key Management Module.

Implements envelope encryption:
- A MASTER key (from environment variable) wraps/unwraps per-node Data Encryption Keys (DEKs).
- DEKs are stored encrypted in the database.
- Key metadata (creation, rotation, active status) is tracked in the encryption_keys table.

This ensures that even if the database is compromised, the encrypted DEKs cannot be used
without the master key, which is stored outside the database.
"""

import os
import base64
from datetime import datetime
from security_modules.encryption import generate_key, encrypt_data, decrypt_data


def get_master_key() -> bytes:
    """
    Retrieve the master encryption key from environment variables.
    The key must be a 64-character hex string (representing 32 bytes).

    Raises:
        ValueError: If MASTER_ENCRYPTION_KEY is not set or invalid.
    """
    hex_key = os.getenv("MASTER_ENCRYPTION_KEY")
    if not hex_key:
        raise ValueError(
            "MASTER_ENCRYPTION_KEY environment variable is not set. "
            "Generate one with: python -c \"import os; print(os.urandom(32).hex())\""
        )
    if len(hex_key) != 64:
        raise ValueError(
            f"MASTER_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes). Got {len(hex_key)}."
        )
    return bytes.fromhex(hex_key)


def wrap_key(dek: bytes, master_key: bytes) -> str:
    """
    Wrap (encrypt) a Data Encryption Key using the master key.

    Args:
        dek: The raw DEK bytes to wrap.
        master_key: The master key bytes.

    Returns:
        Base64-encoded wrapped key string (suitable for DB storage).
    """
    encrypted = encrypt_data(dek, master_key)
    return base64.b64encode(encrypted).decode("utf-8")


def unwrap_key(wrapped_dek: str, master_key: bytes) -> bytes:
    """
    Unwrap (decrypt) a Data Encryption Key using the master key.

    Args:
        wrapped_dek: Base64-encoded wrapped key from wrap_key().
        master_key: The master key bytes.

    Returns:
        The raw DEK bytes.
    """
    encrypted = base64.b64decode(wrapped_dek.encode("utf-8"))
    return decrypt_data(encrypted, master_key)


class KeyManager:
    """
    Centralized key management service.

    Manages per-node Data Encryption Keys (DEKs) using envelope encryption.
    The master key protects all DEKs, and key metadata is tracked in the database.
    """

    def __init__(self, db_session_factory):
        """
        Args:
            db_session_factory: SQLAlchemy sessionmaker for database access.
        """
        self.master_key = get_master_key()
        self.db_session_factory = db_session_factory
        self._key_cache = {}  # node_id -> (key_id, dek_bytes)

    def generate_node_key(self, node_id: str, db) -> dict:
        """
        Generate a new Data Encryption Key for a storage node.

        Args:
            node_id: Identifier for the storage node (e.g., 'node_1').
            db: Active database session.

        Returns:
            Dict with key_id, wrapped_key, and node_id.
        """
        from application_server_models import EncryptionKey  # Avoid circular import

        dek = generate_key()
        key_id = f"{node_id}_key_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        wrapped = wrap_key(dek, self.master_key)

        # Deactivate previous keys for this node
        db.query(EncryptionKey).filter(
            EncryptionKey.node_id == node_id,
            EncryptionKey.is_active == True
        ).update({"is_active": False, "rotated_at": datetime.utcnow()})

        # Store new key metadata
        key_record = EncryptionKey(
            key_id=key_id,
            key_purpose="data",
            is_active=True,
            node_id=node_id,
            wrapped_key=wrapped,
        )
        db.add(key_record)
        db.commit()

        # Update cache
        self._key_cache[node_id] = (key_id, dek)

        return {"key_id": key_id, "wrapped_key": wrapped, "node_id": node_id}

    def get_active_key(self, node_id: str, db) -> tuple:
        """
        Get the active DEK for a storage node.

        Args:
            node_id: The storage node identifier.
            db: Active database session.

        Returns:
            Tuple of (key_id, dek_bytes).

        Raises:
            ValueError: If no active key exists for the node.
        """
        # Check cache first
        if node_id in self._key_cache:
            return self._key_cache[node_id]

        from application_server_models import EncryptionKey

        key_record = db.query(EncryptionKey).filter(
            EncryptionKey.node_id == node_id,
            EncryptionKey.is_active == True
        ).first()

        if not key_record:
            # Auto-generate a key if none exists
            result = self.generate_node_key(node_id, db)
            return (result["key_id"], self._key_cache[node_id][1])

        dek = unwrap_key(key_record.wrapped_key, self.master_key)
        self._key_cache[node_id] = (key_record.key_id, dek)
        return (key_record.key_id, dek)

    def rotate_key(self, node_id: str, db) -> dict:
        """
        Rotate the encryption key for a storage node.
        Generates a new key AND re-encrypts all files on that node.

        Args:
            node_id: The storage node identifier.
            db: Active database session.

        Returns:
            Dict with old_key_id, new_key_id, and files_re_encrypted count.
        """
        from application_server_models import EncryptionKey, EncryptedFile

        # Get old key
        old_key_record = db.query(EncryptionKey).filter(
            EncryptionKey.node_id == node_id,
            EncryptionKey.is_active == True
        ).first()

        old_key_id = old_key_record.key_id if old_key_record else None
        old_dek = None
        if old_key_record and old_key_record.wrapped_key:
            old_dek = unwrap_key(old_key_record.wrapped_key, self.master_key)

        # Generate new key
        new_key_info = self.generate_node_key(node_id, db)
        new_key_id = new_key_info["key_id"]
        new_dek = self._key_cache[node_id][1]

        # Re-encrypt all files on this node
        files_count = 0
        if old_dek:
            files = db.query(EncryptedFile).filter(
                EncryptedFile.storage_node == node_id,
                EncryptedFile.encryption_key_id == old_key_id
            ).all()

            for f in files:
                try:
                    plaintext = decrypt_data(f.encrypted_content, old_dek)
                    f.encrypted_content = encrypt_data(plaintext, new_dek)
                    f.encryption_key_id = new_key_id
                    f.updated_at = datetime.utcnow()
                    files_count += 1
                except Exception as e:
                    print(f"Warning: Failed to re-encrypt file {f.id}: {e}")

            db.commit()

        return {
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "files_re_encrypted": files_count,
        }

    def clear_cache(self):
        """Clear the in-memory key cache (e.g., after rotation)."""
        self._key_cache.clear()
