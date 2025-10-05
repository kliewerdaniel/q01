"""
Kyber Key Encapsulation Mechanism (KEM) Implementation

Kyber is a post-quantum key agreement algorithm standardized by NIST.
This module provides key generation, encapsulation, and decapsulation functions.
"""

import oqs
from oqs import KEM
from typing import Dict, Tuple, bytes, Optional
import logging

logger = logging.getLogger(__name__)

# Available Kyber variants
KYBER_VARIANTS = ['Kyber512', 'Kyber768', 'Kyber1024']

class KyberKEM:
    """
    Wrapper for Kyber KEM operations.
    
    Kyber enables secure key exchange that is resistant to quantum attacks.
    """
    
    def __init__(self, variant: str = 'Kyber1024'):
        """
        Initialize Kyber KEM with specified variant.
        
        Args:
            variant (str): Kyber variant ('Kyber512', 'Kyber768', 'Kyber1024')
        """
        if variant not in KYBER_VARIANTS:
            raise ValueError(f"Unsupported Kyber variant. Choose from: {KYBER_VARIANTS}")
        
        self.variant = variant
        try:
            self.kem = KEM(variant)
            logger.info(f"Initialized Kyber KEM: {variant}")
        except Exception as e:
            logger.error(f"Failed to initialize Kyber {variant}: {e}")
            raise ValueError(f"Kyber {variant} not supported on this platform")
        
    def keygen(self, explain: bool = False) -> Dict[str, bytes]:
        """
        Generate public-private key pair.
        
        Args:
            explain (bool): Print explanatory output
            
        Returns:
            Dict[str, bytes]: Key pair with 'public', 'private' keys
        """
        if explain:
            print("=== Kyber Key Generation ===")
            print("Phase 1: Public-Private Key Pair Creation")
            print(f"Algorithm: {self.variant}")
            print("Public key: for encryption (can be shared)")
            print("Private key: for decryption (keep secret)")
            
        try:
            public_key, private_key = self.kem.keypair()
            
            if explain:
                print(f"Generated key pair for {self.variant}")
                print(f"Public key length: {len(public_key)} bytes")
                print(f"Private key length: {len(private_key)} bytes")
                
            logger.info(f"Generated Kyber key pair: {self.variant}")
            
            return {
                'public': public_key,
                'private': private_key
            }
            
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise
    
    def encapsulate(self, public_key: bytes, explain: bool = False) -> Tuple[bytes, bytes]:
        """
        Encapsulate symmetric key using recipient's public key.
        
        Args:
            public_key (bytes): Recipient's public key
            explain (bool): Print explanations
            
        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
        """
        if explain:
            print("\n=== Kyber Encapsulation ===")
            print("Generate ephemeral key pair")
            print("Encapsulate shared secret for recipient")
            print("Outputs: ciphertext + shared secret")
            
        try:
            ciphertext, shared_secret = self.kem.encaps(public_key)
            
            if explain:
                print("Generated ephemeral key and ciphertext")
                print(f"Ciphertext length: {len(ciphertext)} bytes")
                print(f"Shared secret length: {len(shared_secret)} bytes")
                
            logger.info("Kyber encapsulation successful")
            
            return ciphertext, shared_secret
            
        except Exception as e:
            logger.error(f"Encapsulation failed: {e}")
            raise
    
    def decapsulate(self, ciphertext: bytes, private_key: bytes, explain: bool = False) -> bytes:
        """
        Decapsulate shared secret using private key.
        
        Args:
            ciphertext (bytes): Encrypted ciphertext
            private_key (bytes): Private key for decapsulation
            explain (bool): Print explanations
            
        Returns:
            bytes: Shared secret
        """
        if explain:
            print("\n=== Kyber Decapsulation ===")
            print("Use private key to recover shared secret")
            print("Input: ciphertext + private key")
            print("Output: original shared secret")
            
        try:
            shared_secret = self.kem.decaps(ciphertext, private_key)
            
            if explain:
                print("Shared secret successfully recovered")
                print(f"Shared secret length: {len(shared_secret)} bytes")
                
            logger.info("Kyber decapsulation successful")
            
            return shared_secret
            
        except Exception as e:
            logger.error(f"Decapsulation failed: {e}")
            raise

def kyber_keygen(algorithm: str = 'Kyber1024', explain: bool = False) -> Dict[str, bytes]:
    """
    Convenience function for key generation.
    
    Args:
        algorithm (str): Kyber variant
        explain (bool): Enable explanations
        
    Returns:
        Dict[str, bytes]: Key pair
    """
    kem = KyberKEM(algorithm)
    return kem.keygen(explain)
