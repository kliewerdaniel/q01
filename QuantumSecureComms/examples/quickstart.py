#!/usr/bin/env python3
"""
QuantumSecureComms Quickstart Example

This script demonstrates the basic usage of each quantum cryptography component.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from qsecure.qrng.qrng import QuantumRNG, generate_random_bits
from qsecure.qkd.bb84 import simulate_bb84
from qsecure.pqc.kyber import kyber_keygen
from qsecure.pqc.dilithium import dilithium_keygen
from qsecure.hybrid.hybrid import HybridCrypto

def demo_qrng():
    """Demonstrate Quantum Random Number Generation."""
    print("🔐 Quantum Random Number Generation Demo")
    print("=" * 50)

    qrng = QuantumRNG()
    bits, entropy = qrng.generate_random_bits(16, explain=True)

    print(f"Generated bits: {''.join(map(str, bits))}")
    print(f"Shannon entropy: {entropy:.4f}")
    print()

def demo_bb84():
    """Demonstrate BB84 QKD protocol."""
    print("🔑 BB84 Quantum Key Distribution Demo")
    print("=" * 50)

    key, qber, eve_detected = simulate_bb84(256, explain=True)

    print(f"Final shared key: {''.join(map(str, key[:32]))}...")
    print(f"QBER: {qber:.4f}")
    print(f"Eavesdropping detected: {eve_detected}")
    print()

def demo_kyber():
    """Demonstrate Kyber KEM."""
    print("🔐 Kyber Key Encapsulation Mechanism Demo")
    print("=" * 50)

    keys = kyber_keygen('Kyber1024', explain=True)

    # Use Kyber class directly
    from qsecure.pqc.kyber import KyberKEM
    kem = KyberKEM('Kyber1024')
    ciphertext, shared_secret = kem.encapsulate(keys['public'], explain=True)

    recovered_secret = kem.decapsulate(ciphertext, keys['private'], explain=True)

    print("✅ Shared secret successfully encapsulated and decapsulated")
    print()

def demo_dilithium():
    """Demonstrate Dilithium signature."""
    print("🖋️ Dilithium Digital Signature Demo")
    print("=" * 50)

    keys = dilithium_keygen('Dilithium3', explain=True)

    message = b"Hello, Quantum World!"
    from qsecure.pqc.dilithium import DilithiumSignature
    sig = DilithiumSignature('Dilithium3')
    signature = sig.sign(message, keys['private'], explain=True)

    is_valid = sig.verify(message, signature, keys['public'], explain=True)

    print(f"Message authenticity: {is_valid}")
    print()

def demo_hybrid_crypto():
    """Demonstrate hybrid cryptography."""
    print("🔒 Hybrid Cryptography Demo")
    print("=" * 50)

    # For demo, use random secrets (in practice, from QKD and KEM)
    hybrid = HybridCrypto()

    plaintext = "This is a secret message protected by quantum resilience!"
    ciphertext, nonce, tag, salt = hybrid.encrypt_data(plaintext.encode(), explain=True)

    decrypted = hybrid.decrypt_data(ciphertext, nonce, tag, salt, explain=True)

    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted.decode()}")
    print(f"Integrity preserved: {plaintext == decrypted.decode()}")
    print()

def main():
    """Run all demonstrations."""
    print("🚀 QuantumSecureComms Quickstart")
    print("A demonstration of quantum-resilient cryptographic protocols")
    print("=" * 60)
    print()

    try:
        demo_qrng()
        demo_bb84()
        demo_kyber()
        demo_dilithium()
        demo_hybrid_crypto()

        print("✅ All demonstrations completed successfully!")
        print()
        print("For more information:")
        print("- See README.md for usage instructions")
        print("- Run 'qsecure --help' for CLI commands")
        print("- Check the tests/ directory for unit tests")

    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please ensure all dependencies are installed:")
        print("pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
