"""
SPHINCS+ Digital Signature Algorithm Implementation

SPHINCS+ is a post-quantum signature algorithm standardized by NIST.
This module provides key generation, signing, and verification functions.
"""

import oqs
from oqs import Signature
from typing import Dict
import logging

logger = logging.getLogger(__name__)

# Available SPHINCS+ variants (haraka and sha256)
SPHINCS_VARIANTS = [
    'SPHINCS+-Haraka-128f-robust',
    'SPHINCS+-Haraka-192f-robust',
    'SPHINCS+-Haraka-256f-robust',
    'SPHINCS+-SHA256-128f-robust',
    'SPHINCS+-SHA256-192f-robust',
    'SPHINCS+-SHA256-256f-robust',
    # Fast variants
    'SPHINCS+-Haraka-128f-simple',
    'SPHINCS+-SHA256-128f-simple'
]

class SPHINCSSignature:
    """
    Wrapper for SPHINCS+ digital signature operations.
    
    SPHINCS+ provides quantum-resistant hash-based signatures with minimal trust assumptions.
    Unlike Dilithium, SPHINCS+ is stateless and based on hash functions.
    """
    
    def __init__(self, variant: str = 'SPHINCS+-SHA256-128f-robust'):
        """
        Initialize SPHINCS+ signature with specified variant.
        
        Args:
            variant (str): SPHINCS+ variant (see SPHINCS_VARIANTS)
        """
        if variant not in SPHINCS_VARIANTS:
            raise ValueError(f"Unsupported SPHINCS+ variant. Choose from: {SPHINCS_VARIANTS}")
        
        self.variant = variant
        try:
            self.sig = Signature(variant)
            logger.info(f"Initialized SPHINCS+ Signature: {variant}")
        except Exception as e:
            logger.error(f"Failed to initialize SPHINCS+ {variant}: {e}")
            raise ValueError(f"SPHINCS+ {variant} not supported on this platform")
        
    def keygen(self, explain: bool = False) -> Dict[str, bytes]:
        """
        Generate public-private key pair.
        
        Args:
            explain (bool): Print explanatory output
            
        Returns:
            Dict[str, bytes]: Key pair with 'public', 'private' keys
        """
        if explain:
            print("=== SPHINCS+ Key Generation ===")
            print("Phase 1: Public-Private Key Pair Creation")
            print(f"Algorithm: {self.variant}")
            print("Public key: for signature verification (share freely)")
            print("Private key: for signing messages (keep secret, one-time use recommended)")
            print("Security: hash-based, stateless, quantum-resistant")
            
        try:
            public_key, private_key = self.sig.keypair()
            
            if explain:
                print(f"Generated key pair for {self.variant}")
                print(f"Public key length: {len(public_key)} bytes")
                print(f"Private key length: {len(private_key)} bytes")
                print("XHSS (Extended Hash-Based Signature Standard)")
                
            logger.info(f"Generated SPHINCS+ key pair: {self.variant}")
            
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
            print("\n=== SPHINCS+ Signing ===")
            print("Use private key to sign message")
            print("Algorithm: hash-based, stateless")
            print("Security: quantum-resistant without lattice assumptions")
            
        try:
            signature = self.sig.sign(message, private_key)
            
            if explain:
                print("Message signed successfully")
                print(f"Message length: {len(message)} bytes")
                print(f"Signature length: {len(signature)} bytes")
                
            logger.info("SPHINCS+ signing successful")
            
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
            print("\n=== SPHINCS+ Verification ===")
            print("Use public key to verify signature")
            print("Hash-based cryptography with collision resistance")
            
        try:
            is_valid = self.sig.verify(message, signature, public_key)
            
            if explain:
                if is_valid:
                    print("✓ Signature verified successfully")
                    print("Message integrity and authenticity confirmed")
                else:
                    print("✗ Signature verification failed")
                    print("Message may be corrupted or signature invalid")
                
            logger.info(f"SPHINCS+ verification: {'passed' if is_valid else 'failed'}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False

def sphincs_keygen(algorithm: str = 'SPHINCS+-SHA256-128f-robust', explain: bool = False) -> Dict[str, bytes]:
    """
    Convenience function for key generation.
    
    Args:
        algorithm (str): SPHINCS+ variant
        explain (bool): Enable explanations
        
    Returns:
        Dict[str, bytes]: Key pair
    """
    sig = SPHINCSSignature(algorithm)
    return sig.keygen(explain)

def sphincs_sign(message: bytes, private_key: bytes, algorithm: str = 'SPHINCS+-SHA256-128f-robust', explain: bool = False) -> bytes:
    """
    Convenience function for signing.
    
    Args:
        message (bytes): Message to sign
        private_key (bytes): Private key
        algorithm (str): SPHINCS+ variant
        explain (bool): Enable explanations
        
    Returns:
        bytes: Signature
    """
    sig = SPHINCSSignature(algorithm)
    return sig.sign(message, private_key, explain)

def sphincs_verify(message: bytes, signature: bytes, public_key: bytes, algorithm: str = 'SPHINCS+-SHA256-128f-robust', explain: bool = False) -> bool:
    """
    Convenience function for verification.
    
    Args:
        message (bytes): Original message
        signature (bytes): Signature
        public_key (bytes): Public key
        algorithm (str): SPHINCS+ variant
        explain (bool): Enable explanations
        
    Returns:
        bool: Verification result
    """
    sig = SPHINCSSignature(algorithm)
    return sig.verify(message, signature, public_key, explain)
