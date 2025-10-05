"""
Dilithium Digital Signature Algorithm Implementation

Dilithium is a post-quantum signature algorithm standardized by NIST.
This module provides key generation, signing, and verification functions.
"""

import oqs
from oqs import Signature
from typing import Dict, bytes, bool
import logging

logger = logging.getLogger(__name__)

# Available Dilithium variants
DILITHIUM_VARIANTS = ['Dilithium2', 'Dilithium3', 'Dilithium5']

class DilithiumSignature:
    """
    Wrapper for Dilithium digital signature operations.
    
    Dilithium provides quantum-resistant digital signatures with EUF-CMA security.
    """
    
    def __init__(self, variant: str = 'Dilithium3'):
        """
        Initialize Dilithium signature with specified variant.
        
        Args:
            variant (str): Dilithium variant ('Dilithium2', 'Dilithium3', 'Dilithium5')
        """
        if variant not in DILITHIUM_VARIANTS:
            raise ValueError(f"Unsupported Dilithium variant. Choose from: {DILITHIUM_VARIANTS}")
        
        self.variant = variant
        try:
            self.sig = Signature(variant)
            logger.info(f"Initialized Dilithium Signature: {variant}")
        except Exception as e:
            logger.error(f"Failed to initialize Dilithium {variant}: {e}")
            raise ValueError(f"Dilithium {variant} not supported on this platform")
        
    def keygen(self, explain: bool = False) -> Dict[str, bytes]:
        """
        Generate public-private key pair.
        
        Args:
            explain (bool): Print explanatory output
            
        Returns:
            Dict[str, bytes]: Key pair with 'public', 'private' keys
        """
        if explain:
            print("=== Dilithium Key Generation ===")
            print("Phase 1: Public-Private Key Pair Creation")
            print(f"Algorithm: {self.variant}")
            print("Public key: for signature verification (share freely)")
            print("Private key: for signing messages (keep secret)")
            
        try:
            public_key, private_key = self.sig.keypair()
            
            if explain:
                print(f"Generated key pair for {self.variant}")
                print(f"Public key length: {len(public_key)} bytes")
                print(f"Private key length: {len(private_key)} bytes")
                print("Security level: EUF-CMA (Existentially Unforgeable against Chosen Message Attacks)")
                
            logger.info(f"Generated Dilithium key pair: {self.variant}")
            
            return {
                'public': public_key,
                'private': private_key
            }
            
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise
    
    def sign(self, message: bytes, private_key: bytes, explain: bool = False) -> bytes:
        """
        Sign message using private key.
        
        Args:
            message (bytes): Message to sign
            private_key (bytes): Private key for signing
            explain (bool): Print explanations
            
        Returns:
            bytes: Digital signature
        """
        if explain:
            print("\n=== Dilithium Signing ===")
            print("Use private key to sign message")
            print("Output: cryptographic signature")
            print("Security: quantum-resistant, EUF-CMA secure")
            
        try:
            signature = self.sig.sign(message, private_key)
            
            if explain:
                print("Message signed successfully")
                print(f"Message length: {len(message)} bytes")
                print(f"Signature length: {len(signature)} bytes")
                
            logger.info("Dilithium signing successful")
            
            return signature
            
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes, explain: bool = False) -> bool:
        """
        Verify signature using public key.
        
        Args:
            message (bytes): Original message
            signature (bytes): Digital signature to verify
            public_key (bytes): Public key for verification
            explain (bool): Print explanations
            
        Returns:
            bool: True if signature is valid
        """
        if explain:
            print("\n=== Dilithium Verification ===")
            print("Use public key to verify signature")
            print("Checks: signature integrity and message authenticity")
            
        try:
            is_valid = self.sig.verify(message, signature, public_key)
            
            if explain:
                if is_valid:
                    print("✓ Signature verified successfully")
                    print("Message integrity and authenticity confirmed")
                else:
                    print("✗ Signature verification failed")
                    print("Message may be corrupted or signature invalid")
                
            logger.info(f"Dilithium verification: {'passed' if is_valid else 'failed'}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False

def dilithium_keygen(algorithm: str = 'Dilithium3', explain: bool = False) -> Dict[str, bytes]:
    """
    Convenience function for key generation.
    
    Args:
        algorithm (str): Dilithium variant
        explain (bool): Enable explanations
        
    Returns:
        Dict[str, bytes]: Key pair
    """
    sig = DilithiumSignature(algorithm)
    return sig.keygen(explain)

def dilithium_sign(message: bytes, private_key: bytes, algorithm: str = 'Dilithium3', explain: bool = False) -> bytes:
    """
    Convenience function for signing.
    
    Args:
        message (bytes): Message to sign
        private_key (bytes): Private key
        algorithm (str): Dilithium variant
        explain (bool): Enable explanations
        
    Returns:
        bytes: Signature
    """
    sig = DilithiumSignature(algorithm)
    return sig.sign(message, private_key, explain)

def dilithium_verify(message: bytes, signature: bytes, public_key: bytes, algorithm: str = 'Dilithium3', explain: bool = False) -> bool:
    """
    Convenience function for verification.
    
    Args:
        message (bytes): Original message
        signature (bytes): Signature
        public_key (bytes): Public key
        algorithm (str): Dilithium variant
        explain (bool): Enable explanations
        
    Returns:
        bool: Verification result
    """
    sig = DilithiumSignature(algorithm)
    return sig.verify(message, signature, public_key, explain)
