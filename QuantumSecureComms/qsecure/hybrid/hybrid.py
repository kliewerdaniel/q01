"""
Hybrid Cryptography Implementation

This module merges post-quantum and quantum key distribution technologies
to create a robust hybrid encryption scheme using AES-256-GCM.
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from typing import Tuple, bytes, Optional
import logging

logger = logging.getLogger(__name__)

class HybridCrypto:
    """
    Hybrid cryptographic system combining PQC/KEM, QKD-derived keys,
    and classical symmetric encryption via HKDF and AES-GCM.
    """
    
    def __init__(self, qkd_secret: Optional[bytes] = None, kem_secret: Optional[bytes] = None):
        """
        Initialize hybrid crypto with combined secrets.
        
        Args:
            qkd_secret (bytes): Shared secret from QKD protocol
            kem_secret (bytes): Shared secret from PQC KEM
        """
        self.qkd_secret = qkd_secret or os.urandom(32)  # 256-bit fallback
        self.kem_secret = kem_secret or os.urandom(32)  # 256-bit fallback
        
        # Combined input for HKDF
        self.master_secret = self._combine_secrets()
        
    def _combine_secrets(self) -> bytes:
        """
        Combine QKD and PQC secrets securely.
        
        Uses HKDF with a salt to derive a master secret.
        
        Returns:
            bytes: Combined master secret
        """
        # Use SHA-256 HKDF to combine secrets
        hkdf = HKDF(
            algorithm=hashlib.sha256,
            length=32,  # 256 bits
            salt=b'QuantumSecureComms',  # Fixed salt for determinism
            info=b'hybrid_master_secret',
            backend=default_backend()
        )
        
        input_key = self.qkd_secret + self.kem_secret
        master_secret = hkdf.derive(input_key)
        
        logger.info("Generated hybrid master secret")
        return master_secret
    
    def _derive_encrypt_key(self, key_id: bytes, salt: bytes) -> bytes:
        """
        Derive encryption key from master secret.
        
        Args:
            key_id (bytes): Unique identifier for key derivation
            salt (bytes): Random salt for additional entropy
            
        Returns:
            bytes: AES-256 encryption key
        """
        hkdf = HKDF(
            algorithm=hashlib.sha256,
            length=32,  # 256 bits for AES-256
            salt=salt,
            info=key_id,
            backend=default_backend()
        )
        
        encrypt_key = hkdf.derive(self.master_secret)
        return encrypt_key
    
    def encrypt_data(self, plaintext: bytes, key_id: Optional[bytes] = None, explain: bool = False) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Encrypt data using hybrid AES-256-GCM encryption.

        Args:
            plaintext (bytes): Data to encrypt
            key_id (bytes): Key derivation identifier
            explain (bool): Print explanations

        Returns:
            Tuple[bytes, bytes, bytes, bytes]: (ciphertext, nonce, tag, salt)
        """
        if explain:
            print("=== Hybrid Encryption ===")
            print("Phase 1: HKDF Key Derivation from QKD + PQC secrets")
            print("Phase 2: AES-256-GCM authenticated encryption")
            print("Hardware acceleration recommended for performance")

        key_id = key_id or b'hybrid_encrypt'
        salt = os.urandom(32)  # Random salt per encryption

        # Derive encryption key
        encrypt_key = self._derive_encrypt_key(key_id, salt)

        # Generate random nonce (96 bits for AES-GCM)
        nonce = os.urandom(12)

        # Create cipher
        cipher = Cipher(algorithms.AES(encrypt_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt with associated data (salt for key recovery)
        encryptor.authenticate_additional_data(salt)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        if explain:
            print(f"Plaintext length: {len(plaintext)} bytes")
            print(f"Ciphertext length: {len(ciphertext)} bytes")
            print(f"Authentication tag: {tag.hex()[:16]}...")

        logger.info("Hybrid encryption completed")

        # Return ciphertext, nonce, tag, and salt for decryption
        return ciphertext, nonce, tag, salt
    
    def decrypt_data(self, ciphertext: bytes, nonce: bytes, tag: bytes, salt: bytes, key_id: Optional[bytes] = None, explain: bool = False) -> bytes:
        """
        Decrypt data using hybrid AES-256-GCM decryption.
        
        Args:
            ciphertext (bytes): Encrypted data
            nonce (bytes): Nonce used for encryption
            tag (bytes): Authentication tag
            salt (bytes): Salt used for key derivation
            key_id (bytes): Key derivation identifier
            explain (bool): Print explanations
            
        Returns:
            bytes: Decrypted plaintext
        """
        if explain:
            print("=== Hybrid Decryption ===")
            print("Phase 1: HKDF Key Derivation (recreate same key)")
            print("Phase 2: AES-256-GCM authenticated decryption")
            print("Phase 3: Verify authenticity and integrity")
            
        key_id = key_id or b'hybrid_encrypt'
        
        # Recreate the same encryption key
        encrypt_key = self._derive_encrypt_key(key_id, salt)
        
        # Create cipher for decryption
        cipher = Cipher(algorithms.AES(encrypt_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Verify with associated data
        decryptor.authenticate_additional_data(salt)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        if explain:
            print(f"Ciphertext length: {len(ciphertext)} bytes")
            print(f"Plaintext length: {len(plaintext)} bytes")
            print("✓ Authentication and integrity verified")
            
        logger.info("Hybrid decryption completed")
        
        return plaintext

def encrypt_file(filepath: str, hybrid_crypto: HybridCrypto, explain: bool = False) -> Tuple[str, bytes, bytes]:
    """
    Encrypt a file using hybrid cryptography.
    
    Args:
        filepath (str): Path to file to encrypt
        hybrid_crypto (HybridCrypto): Hybrid crypto instance
        explain (bool): Print explanations
        
    Returns:
        Tuple[str, bytes, bytes]: (encrypted_filepath, nonce, salt)
    """
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, nonce, tag, salt = hybrid_crypto.encrypt_data(plaintext, explain=explain)

    encrypted_file = filepath + '.encrypted'
    with open(encrypted_file, 'wb') as f:
        # Format: salt (32) + nonce (12) + tag (16) + ciphertext
        f.write(salt + nonce + tag + ciphertext)

    logger.info(f"File encrypted: {filepath} -> {encrypted_file}")
    return encrypted_file, nonce, salt

def decrypt_file(encrypted_filepath: str, hybrid_crypto: HybridCrypto, explain: bool = False) -> str:
    """
    Decrypt a file using hybrid cryptography.
    
    Args:
        encrypted_filepath (str): Path to encrypted file
        hybrid_crypto (HybridCrypto): Hybrid crypto instance
        explain (bool): Print explanations
        
    Returns:
        str: Decrypted filepath
    """
    with open(encrypted_filepath, 'rb') as f:
        data = f.read()
    
    # Parse format
    salt = data[:32]
    nonce = data[32:44]  # 32 + 12 = 44
    tag = data[44:60]    # 44 + 16 = 60
    ciphertext = data[60:]
    
    plaintext = hybrid_crypto.decrypt_data(ciphertext, nonce, tag, salt, explain=explain)
    
    decrypted_file = encrypted_filepath.replace('.encrypted', '_decrypted')
    with open(decrypted_file, 'wb') as f:
        f.write(plaintext)
    
    logger.info(f"File decrypted: {encrypted_filepath} -> {decrypted_file}")
    return decrypted_file
