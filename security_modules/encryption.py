"""
Encryption module for data-at-rest protection.

Uses AES-256-GCM (Authenticated Encryption with Associated Data) to ensure
both confidentiality and integrity of stored data. Each encryption operation
generates a unique nonce (IV) to prevent ciphertext analysis.

Blob format: [12-byte nonce][16-byte tag][ciphertext]
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    """Generate a new 256-bit (32-byte) AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext bytes using AES-256-GCM.

    Args:
        plaintext: The data to encrypt.
        key: A 32-byte AES key.

    Returns:
        Encrypted blob: nonce (12 bytes) + tag (16 bytes, appended by GCM) + ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    # GCM appends the 16-byte tag to the ciphertext automatically
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext_with_tag


def decrypt_data(encrypted_blob: bytes, key: bytes) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted blob.

    Args:
        encrypted_blob: The output of encrypt_data (nonce + tag + ciphertext).
        key: The same 32-byte AES key used for encryption.

    Returns:
        The original plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If the key is wrong or data was tampered with.
    """
    nonce = encrypted_blob[:12]
    ciphertext_with_tag = encrypted_blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def encrypt_field(value: str, key: bytes) -> str:
    """
    Encrypt a string field and return a base64-encoded representation.
    Suitable for storing encrypted strings in database text columns.

    Args:
        value: The string to encrypt.
        key: A 32-byte AES key.

    Returns:
        Base64-encoded encrypted string.
    """
    encrypted = encrypt_data(value.encode("utf-8"), key)
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_field(encrypted_value: str, key: bytes) -> str:
    """
    Decrypt a base64-encoded encrypted field back to a string.

    Args:
        encrypted_value: Base64-encoded encrypted string from encrypt_field.
        key: The same 32-byte AES key used for encryption.

    Returns:
        The original plaintext string.
    """
    encrypted_blob = base64.b64decode(encrypted_value.encode("utf-8"))
    return decrypt_data(encrypted_blob, key).decode("utf-8")
