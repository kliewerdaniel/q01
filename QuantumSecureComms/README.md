# QuantumSecureComms

A research-grade, educational framework demonstrating quantum-resilient cryptographic protocols. This project integrates Post-Quantum Cryptography (PQC) with simulated Quantum Key Distribution (QKD) to build hybrid secure communication systems.

## Features

- **Quantum Random Number Generation (QRNG)**: Generate true random bits using Qiskit simulations.
- **Quantum Key Distribution (QKD)**: Implement BB84 and E91 protocols with eavesdropping detection.
- **Post-Quantum Cryptography (PQC)**: Integrate Kyber, Dilithium, and SPHINCS+ via liboqs-python.
- **Hybrid Cryptography**: Combine QKD and PQC keys with HKDF for AES-256-GCM encryption.
- **Secure Chat Application**: Real-time messaging over TCP with automated key exchange.
- **Educational Tools**: Inline comments, verbose modes, and step-by-step explanations.

## Installation

Requires Python 3.9+.

```bash
pip install -r requirements.txt
# For development
pip install -r requirements-dev.txt
```

## Usage

```bash
# Generate quantum random bits
qsecure qrng --bits 256

# Simulate BB84 QKD
qsecure qkd --protocol BB84 --bits 1024

# Generate Kyber keypairs
qsecure keygen --algorithm Kyber1024

# Encrypt file with hybrid crypto
qsecure encrypt --input message.txt --hybrid

# Start secure chat
qsecure chat --name Alice --port 5000
```

## Project Structure

- `qsecure/`: Main package modules
  - `pqc/`: Post-Quantum algorithms (Kyber, Dilithium, SPHINCS+)
  - `qkd/`: Quantum Key Distribution (BB84, E91)
  - `qrng/`: Quantum Random Number Generation
  - `hybrid/`: Hybrid classical-quantum crypto
  - `comms/`: Secure messaging and channels
  - `utils/`: Cryptographic utilities and key management

## Security Model

This framework demonstrates quantum-resilient cryptography:
- PQC algorithms standardized by NIST.
- QKD protocols simulate secure key exchange over quantum channels.
- Hybrid systems ensure forward secrecy and resistance to classical attacks.

## References

- NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography
- SIPRI Quantum Technology Project: https://www.sipri.org/research/quantum-technology
- Qiskit Quantum SDK: https://qiskit.org/
- liboqs: https://openquantumsafe.org/

## License

MIT License - see LICENSE file.
