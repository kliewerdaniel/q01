# QuantumSecureComms: Post-Quantum Secure Communication Framework

A production-grade implementation of quantum-resilient cryptographic protocols for secure communications, demonstrating practical applications of post-quantum cryptography (PQC), quantum key distribution (QKD) simulation, and quantum-enhanced security mechanisms described in SIPRI's 2025 military and security quantum technologies primer.

## Table of Contents

- [Overview](#overview)
- [Educational Objectives](#educational-objectives)
- [Core Concepts from SIPRI Research](#core-concepts-from-sipri-research)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [Project Roadmap](#project-roadmap)
- [Implementation Milestones](#implementation-milestones)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Overview

QuantumSecureComms is an educational and research-focused toolkit that implements quantum-resilient cryptographic systems to address the imminent threat posed by Cryptographically Relevant Quantum Computers (CRQCs). According to SIPRI's 2025 assessment, Q-day—when quantum computers can break RSA-2048 encryption—may arrive within 8-15 years. This project demonstrates practical defenses against both current harvest-now-decrypt-later (HNDL) attacks and future quantum cryptanalysis.

The system combines:
- **NIST-standardized Post-Quantum Cryptography** (CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+)
- **Simulated Quantum Key Distribution** (BB84, E91 protocols)
- **Hybrid Classical-Quantum Security** (layering PQC with QKD simulation)
- **Quantum Random Number Generation** (QRNG using quantum circuit measurement)
- **Secure Channel Establishment** with quantum-resistant algorithms

This is a **teaching project** designed to help developers understand quantum cryptography concepts through hands-on implementation, not a production security system.

## Educational Objectives

By building this project incrementally, you will learn:

1. **Quantum Computing Fundamentals**: qubits, superposition, entanglement, measurement, quantum gates
2. **Post-Quantum Cryptography**: lattice-based encryption, hash-based signatures, key encapsulation mechanisms
3. **Quantum Key Distribution**: BB84 protocol, eavesdropping detection, unconditional security principles
4. **Quantum Random Number Generation**: extracting true randomness from quantum measurements
5. **Hybrid Cryptographic Systems**: combining classical and quantum-resistant approaches
6. **Security Engineering**: key lifecycle management, secure channel establishment, authentication
7. **Quantum Circuit Design**: using Qiskit to build and simulate quantum protocols

## Core Concepts from SIPRI Research

### The Quantum Cryptographic Threat

**Current Reality** (2025):
- Public-key cryptography (RSA, ECC, Diffie-Hellman) secures most internet communications
- Adversaries are already intercepting encrypted data for future decryption (HNDL strategy)
- Sensitive government/military data must remain confidential for decades

**Q-Day Scenario** (estimated 8-15 years):
- Quantum computers running Shor's algorithm can factor large numbers exponentially faster
- RSA-2048 could be broken in hours instead of billions of years
- All previously harvested encrypted data becomes readable

**Defense Strategy** (implemented in this project):
1. **Post-Quantum Cryptography (PQC)**: Deploy NIST-standardized algorithms resistant to quantum attacks
2. **Quantum Key Distribution (QKD)**: Use quantum physics laws to detect eavesdropping
3. **Hybrid Approach**: Layer PQC + QKD for defense-in-depth

### Quantum Key Distribution Principles

QKD enables two parties to share encryption keys with security guaranteed by quantum physics:

- **BB84 Protocol**: Encodes bits in photon polarization states; any measurement by an eavesdropper disturbs the quantum state
- **Eavesdropping Detection**: Comparing measurement bases reveals interception attempts
- **Unconditional Security**: Not based on computational complexity but physical laws

*Note: This project simulates QKD using Qiskit quantum circuits, not real photonic hardware.*

### Quantum Random Number Generation

True randomness is essential for cryptographic keys. Classical pseudorandom generators can be predicted; quantum measurement outcomes are fundamentally random:

- Measure qubits in superposition states
- Outcomes are truly random per quantum mechanics
- Provides cryptographically secure random bits

## Architecture

```
QuantumSecureComms/
│
├── Core Modules
│   ├── PQC Engine (NIST algorithms)
│   ├── QKD Simulator (BB84/E91 protocols)
│   ├── QRNG Generator (quantum measurement)
│   └── Hybrid Key Manager (PQC + QKD keys)
│
├── Communication Layer
│   ├── Secure Channel (encrypted messaging)
│   ├── Authentication (Dilithium signatures)
│   └── Session Management
│
├── Quantum Simulation
│   ├── Qiskit Circuit Builder
│   ├── Quantum State Preparation
│   └── Measurement & Analysis
│
└── CLI & API
    ├── Key Generation Commands
    ├── Secure Messaging Interface
    └── Protocol Demonstrations
```

## Technologies Used

### Cryptography
- **PQCrypto Libraries**: `liboqs` (Open Quantum Safe) or pure Python implementations
- **NIST PQC Algorithms**: CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (signatures), SPHINCS+ (hash-based signatures)

### Quantum Computing
- **IBM Qiskit**: Quantum circuit simulation and execution
- **Qiskit Aer**: High-performance quantum circuit simulator
- **NumPy/SciPy**: Mathematical operations on quantum states

### Development
- **Python 3.9+**: Primary language
- **Click**: CLI framework
- **pytest**: Testing framework
- **Cryptography**: Additional classical crypto primitives
- **Docker**: Containerized deployment

## Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager
- Git
- (Optional) Docker for containerized deployment

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/YourOrg/QuantumSecureComms.git
cd QuantumSecureComms

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install development dependencies (optional)
pip install -r requirements-dev.txt

# 5. Verify installation
python -m pytest tests/ -v

# 6. Run example
python examples/basic_qkd_demo.py
```

### Requirements.txt (Core Dependencies)

```
qiskit>=1.0.0
qiskit-aer>=0.13.0
numpy>=1.24.0
scipy>=1.10.0
cryptography>=41.0.0
click>=8.1.0
pycryptodome>=3.19.0
liboqs-python>=0.10.0  # NIST PQC algorithms
```

## Usage

### Generate Quantum Random Numbers

```bash
$ qsecure qrng --bits 256
Generated 256 quantum random bits:
10110101001110110...
Entropy: 7.98 bits/byte (theoretical max: 8.0)
```

### Simulate QKD Key Exchange

```bash
$ qsecure qkd --protocol BB84 --bits 1024
=== BB84 Quantum Key Distribution ===
1. Alice prepares 1024 qubits in random bases
2. Bob measures in random bases
3. Basis reconciliation (public channel)
4. Eavesdropping check (QBER analysis)

Quantum Bit Error Rate (QBER): 1.2%
Status: SECURE (threshold: 11%)
Final shared key: 512 bits
Key material: a3f8c29d1b4e...
```

### Generate PQC Key Pairs

```bash
$ qsecure keygen --algorithm Kyber1024
=== Post-Quantum Key Generation ===
Algorithm: CRYSTALS-Kyber-1024
Security Level: NIST Level 5 (256-bit quantum security)

Generated:
  Public Key: kyber_pk_20250605.pem (1568 bytes)
  Private Key: kyber_sk_20250605.pem (3168 bytes)
```

### Encrypt/Decrypt Messages (Hybrid Mode)

```bash
# Encrypt with PQC + QKD-derived key
$ qsecure encrypt --input message.txt --recipient alice_pk.pem --hybrid
Establishing hybrid secure channel...
1. QKD key exchange (512 bits)
2. Kyber key encapsulation
3. AES-256-GCM encryption with derived key

Encrypted: message.txt.enc (metadata: hybrid-kyber-qkd)

# Decrypt
$ qsecure decrypt --input message.txt.enc --key alice_sk.pem
Decrypting hybrid ciphertext...
QKD key verification: OK
Kyber decapsulation: OK
Message recovered: "This is a quantum-secure message."
```

### Secure Chat Simulation

```bash
# Terminal 1 (Alice)
$ qsecure chat --name Alice --port 5000
QKD handshake with Bob... OK (512-bit key)
Dilithium signature verification... OK
[Alice] >> Hello from the quantum-secure channel!

# Terminal 2 (Bob)
$ qsecure chat --name Bob --connect localhost:5000
QKD handshake with Alice... OK (512-bit key)
Dilithium signature verification... OK
[Bob] << Hello from the quantum-secure channel!
[Bob] >> This message is safe from quantum computers!
```

## Project Roadmap

### Phase 1: Foundations (Weeks 1-2)
**Goal**: Understand quantum computing basics and set up development environment

**Deliverables**:
- Qiskit installation and first quantum circuits
- Single-qubit and two-qubit gate operations
- Quantum measurement and state visualization
- Basic quantum randomness extraction

**Learning Checkpoints**:
- [ ] Create superposition states with Hadamard gates
- [ ] Implement quantum entanglement (Bell states)
- [ ] Measure quantum states and analyze probability distributions
- [ ] Extract 1000 random bits from quantum measurements

---

### Phase 2: Quantum Random Number Generation (Weeks 3-4)
**Goal**: Build a cryptographically secure QRNG

**Deliverables**:
- QRNG module using multiple quantum circuits
- Entropy analysis and statistical testing
- CLI tool for generating random bytes
- Integration with system crypto libraries

**Implementation Steps**:
1. Design quantum circuits for randomness extraction
2. Implement measurement and bit collection
3. Add post-processing (von Neumann debiasing)
4. Validate randomness with NIST statistical test suite
5. Create command-line interface

**Learning Checkpoints**:
- [ ] Explain why quantum randomness is superior to classical PRNG
- [ ] Implement von Neumann bias correction
- [ ] Pass NIST randomness tests (15 tests)
- [ ] Generate 1MB of quantum random data

---

### Phase 3: BB84 Protocol Implementation (Weeks 5-7)
**Goal**: Simulate complete quantum key distribution

**Deliverables**:
- BB84 protocol with basis selection
- Eavesdropping detection (QBER calculation)
- Privacy amplification techniques
- Network simulation (Alice/Bob/Eve)

**Implementation Steps**:
1. **Qubit Preparation** (Alice):
   - Generate random bits and random bases
   - Encode bits in quantum states (|0⟩, |1⟩, |+⟩, |−⟩)
   - Create quantum circuits for each qubit

2. **Measurement** (Bob):
   - Choose random measurement bases
   - Measure qubits in chosen bases
   - Record measurement outcomes

3. **Sifting** (Classical Channel):
   - Alice and Bob announce bases publicly
   - Keep only bits where bases matched
   - Discard others (expect 50% retention)

4. **Error Checking**:
   - Compare random sample of remaining bits
   - Calculate Quantum Bit Error Rate (QBER)
   - QBER < 11% indicates security (no eavesdropper)

5. **Privacy Amplification**:
   - Apply error correction codes
   - Use hash functions to compress key
   - Final shared secret key

**Learning Checkpoints**:
- [ ] Implement photon polarization encoding in Qiskit
- [ ] Simulate eavesdropper (Eve) measuring qubits
- [ ] Detect eavesdropping via elevated QBER
- [ ] Complete full BB84 exchange with 1024-bit key

---

### Phase 4: Post-Quantum Cryptography (Weeks 8-10)
**Goal**: Integrate NIST-standardized PQC algorithms

**Deliverables**:
- Kyber key encapsulation mechanism (KEM)
- Dilithium digital signatures
- SPHINCS+ hash-based signatures
- Comparison benchmarks vs RSA/ECC

**Implementation Steps**:
1. **Install liboqs**:
   ```bash
   pip install liboqs-python
   ```

2. **Kyber Integration**:
   - Generate Kyber public/private key pairs
   - Encapsulate symmetric keys
   - Decapsulate to recover keys
   - Use for AES encryption

3. **Dilithium Signatures**:
   - Sign messages with Dilithium private key
   - Verify signatures with public key
   - Implement signature-then-encrypt pattern

4. **Performance Testing**:
   - Benchmark key generation time
   - Measure encryption/decryption speed
   - Compare key sizes (RSA vs Kyber)

**Learning Checkpoints**:
- [ ] Explain lattice-based cryptography principles
- [ ] Generate Kyber-1024 key pairs
- [ ] Sign and verify 100 messages with Dilithium
- [ ] Demonstrate Kyber resistance to Shor's algorithm (conceptual)

---

### Phase 5: Hybrid Cryptographic System (Weeks 11-13)
**Goal**: Combine PQC + QKD for defense-in-depth

**Deliverables**:
- Hybrid key derivation function (HKDF)
- Layered encryption (PQC wrapping QKD keys)
- Key lifecycle management
- Secure session establishment protocol

**Implementation Steps**:
1. **Key Derivation**:
   - Combine QKD key + Kyber shared secret
   - Use HKDF (HMAC-based KDF) to derive session keys
   - Implement key rotation policies

2. **Hybrid Encryption**:
   ```python
   # Pseudocode
   qkd_key = bb84_exchange(alice, bob)
   kyber_pk, kyber_sk = kyber_keygen()
   kyber_ct, kyber_ss = kyber_encap(kyber_pk)
   
   master_key = HKDF(qkd_key + kyber_ss)
   plaintext = encrypt_aes_gcm(data, master_key)
   ```

3. **Authentication**:
   - Use Dilithium signatures for identity verification
   - Implement challenge-response protocol
   - Prevent man-in-the-middle attacks

4. **Session Protocol**:
   - Handshake: QKD → Kyber KEM → Dilithium auth
   - Data transfer: AES-256-GCM with derived keys
   - Teardown: Secure key erasure

**Learning Checkpoints**:
- [ ] Design hybrid key derivation scheme
- [ ] Implement complete handshake protocol
- [ ] Test against simulated MITM attack
- [ ] Document security properties of hybrid approach

---

### Phase 6: Secure Communication Application (Weeks 14-16)
**Goal**: Build user-facing secure messaging system

**Deliverables**:
- CLI-based chat application
- Automated QKD + PQC handshake
- Real-time encrypted messaging
- Message authentication and integrity

**Implementation Steps**:
1. **Network Layer**:
   - Socket-based communication (TCP)
   - Message framing protocol
   - Connection state management

2. **Crypto Layer**:
   - Automatic key negotiation
   - Per-message authentication tags
   - Perfect forward secrecy (new keys per session)

3. **User Interface**:
   - Simple chat CLI with Click
   - Display security indicators
   - Show key exchange progress

4. **Error Handling**:
   - Network failure recovery
   - Key agreement timeout handling
   - Tampering detection alerts

**Learning Checkpoints**:
- [ ] Implement TCP socket client/server
- [ ] Automate full hybrid handshake
- [ ] Exchange 100 authenticated messages
- [ ] Demonstrate eavesdropping resistance

---

### Phase 7: Testing & Documentation (Weeks 17-18)
**Goal**: Production-quality testing and comprehensive docs

**Deliverables**:
- Unit tests (90%+ coverage)
- Integration tests (full protocol runs)
- Security audit checklist
- API documentation and tutorials

**Implementation Steps**:
1. **Unit Tests**:
   - Test each quantum circuit independently
   - Verify QRNG entropy
   - Validate PQC correctness

2. **Integration Tests**:
   - End-to-end QKD simulation
   - Hybrid encryption/decryption cycle
   - Multi-user chat scenarios

3. **Security Review**:
   - Static analysis with Bandit
   - Dependency vulnerability scanning
   - Key storage security review

4. **Documentation**:
   - API reference (Sphinx)
   - Tutorial notebooks (Jupyter)
   - Architecture diagrams
   - Threat model document

**Learning Checkpoints**:
- [ ] Achieve 90%+ test coverage
- [ ] Pass all security linters
- [ ] Write 5 tutorial notebooks
- [ ] Document threat model

---

### Phase 8: Advanced Features (Weeks 19-20+)
**Goal**: Cutting-edge enhancements and research directions

**Optional Enhancements**:
- E91 protocol (entanglement-based QKD)
- Quantum digital signatures
- Quantum secret sharing
- Integration with real quantum hardware (IBM Quantum)
- GUI application (PyQt5/Tkinter)
- Multi-party secure computation
- Quantum-resistant blockchain

**Research Extensions**:
- Compare different PQC algorithm families
- Analyze quantum gate error rates impact on QKD
- Implement quantum error correction codes
- Study quantum network topologies

## Implementation Milestones

### Milestone 1: Hello Quantum World
**Deadline**: Week 2  
**Objective**: Run first quantum circuit

```python
from qiskit import QuantumCircuit
from qiskit_aer import Aer

# Create 1-qubit circuit
qc = QuantumCircuit(1, 1)
qc.h(0)  # Hadamard gate (superposition)
qc.measure(0, 0)

# Simulate
backend = Aer.get_backend('qasm_simulator')
job = backend.run(qc, shots=1000)
result = job.result()
counts = result.get_counts()

print(counts)  # Should be ~50/50 split: {'0': 501, '1': 499}
```

**Success Criteria**: 
- Circuit runs without errors
- Measurement outcomes show 50% probability for |0⟩ and |1⟩
- Understand superposition concept

---

### Milestone 2: Quantum Entanglement
**Deadline**: Week 2  
**Objective**: Create and measure Bell states

```python
# Bell state: (|00⟩ + |11⟩)/√2
qc = QuantumCircuit(2, 2)
qc.h(0)           # Superposition on qubit 0
qc.cx(0, 1)       # CNOT: entangle qubits 0 and 1
qc.measure([0, 1], [0, 1])

# Result: only '00' and '11' (never '01' or '10')
```

**Success Criteria**:
- Observe perfect correlation between qubits
- Zero probability for anti-correlated outcomes
- Explain entanglement vs classical correlation

---

### Milestone 3: Working QRNG
**Deadline**: Week 4  
**Objective**: Generate cryptographic random numbers

```bash
$ python qrng.py --bits 256
Output: 32 random bytes (256 bits)
Entropy: 7.97 bits/byte
Statistical tests: PASSED (NIST suite)
```

**Success Criteria**:
- Generate arbitrary-length random bit strings
- Pass at least 10/15 NIST tests
- Implement von Neumann debiasing

---

### Milestone 4: BB84 Simulation (No Eve)
**Deadline**: Week 6  
**Objective**: Complete key exchange between Alice and Bob

```python
# Expected output:
"""
=== BB84 Protocol ===
Alice sent: 1000 qubits
Bob measured: 1000 qubits
Basis reconciliation: 487 matches (48.7%)
Error checking: QBER = 0.4%
Final key length: 450 bits
Key agreement: SUCCESS
"""
```

**Success Criteria**:
- ~50% basis match rate
- QBER < 5% (no eavesdropper)
- Shared key matches between Alice and Bob

---

### Milestone 5: Eavesdropping Detection
**Deadline**: Week 7  
**Objective**: Detect Eve's presence via elevated QBER

```python
# With Eve intercepting:
"""
=== BB84 Protocol (Eve Present) ===
Alice sent: 1000 qubits
Eve intercepted: 1000 qubits (50% wrong basis)
Bob measured: 1000 qubits
Basis reconciliation: 505 matches (50.5%)
Error checking: QBER = 24.8%
Status: ATTACK DETECTED (threshold: 11%)
Protocol ABORTED
"""
```

**Success Criteria**:
- QBER increases to ~25% with Eve
- Successfully detect and abort
- Understand no-cloning theorem

---

### Milestone 6: PQC Key Exchange
**Deadline**: Week 9  
**Objective**: Use Kyber for secure key encapsulation

```python
from liboqs import KEM

# Alice generates keypair
kem = KEM('Kyber1024')
public_key = kem.generate_keypair()

# Bob encapsulates secret
ciphertext, shared_secret_bob = kem.encap_secret(public_key)

# Alice decapsulates
shared_secret_alice = kem.decap_secret(ciphertext)

assert shared_secret_alice == shared_secret_bob
print("PQC key exchange successful!")
```

**Success Criteria**:
- Successfully encapsulate/decapsulate keys
- Verify key agreement
- Benchmark performance vs RSA

---

### Milestone 7: Hybrid Encryption
**Deadline**: Week 12  
**Objective**: Encrypt data using QKD + Kyber hybrid

```python
# Combine keys
qkd_key = bb84_protocol(alice, bob)
kyber_ct, kyber_ss = kyber_kem(bob_pk)
master_key = HKDF(qkd_key, kyber_ss)

# Encrypt with AES-GCM
ciphertext = aes_gcm_encrypt(plaintext, master_key)
```

**Success Criteria**:
- Successfully combine QKD + PQC keys
- Encrypt and decrypt test messages
- Document security properties

---

### Milestone 8: Working Chat App
**Deadline**: Week 16  
**Objective**: Two users exchange messages securely

```bash
# Terminal 1
$ python chat.py --name Alice --port 5000
Waiting for connection...
Bob connected. Performing QKD...
QKD complete (512 bits). Performing Kyber KEM...
Hybrid handshake complete. Dilithium auth OK.
[Alice] >> Hello Bob!

# Terminal 2
$ python chat.py --name Bob --connect localhost:5000
Connecting to Alice...
QKD complete (512 bits). Performing Kyber KEM...
Hybrid handshake complete. Dilithium auth OK.
[Bob] << Hello Bob!
[Bob] >> Hi Alice! This is quantum-secure!
```

**Success Criteria**:
- Automatic handshake
- Real-time bidirectional messaging
- Message authentication
- Clean error handling

---

### Milestone 9: Full Test Suite
**Deadline**: Week 18  
**Objective**: Comprehensive automated testing

```bash
$ pytest tests/ -v --cov=qsecure --cov-report=html

tests/test_qrng.py::test_entropy PASSED
tests/test_bb84.py::test_no_eve PASSED
tests/test_bb84.py::test_with_eve PASSED
tests/test_kyber.py::test_kem PASSED
tests/test_dilithium.py::test_signatures PASSED
tests/test_hybrid.py::test_key_derivation PASSED
tests/test_chat.py::test_handshake PASSED
tests/test_chat.py::test_messaging PASSED

Coverage: 92%
```

**Success Criteria**:
- 90%+ code coverage
- All critical paths tested
- No security linter warnings

---

## Security Considerations

### Known Limitations

This project is **educational** and has important security limitations:

1. **Simulation Only**: QKD uses simulated quantum states, not real photonics. Real implementations face noise, loss, and hardware security issues.

2. **Local Execution**: No protection against local adversaries with physical access.

3. **Implementation Security**: Not audited by cryptographic experts. May contain timing channels, side-channel vulnerabilities, or implementation flaws.

4. **Key Management**: Simplified key storage. Production systems need Hardware Security Modules (HSMs).

5. **Network Security**: Basic transport layer. Production needs TLS + certificate validation.

### Security Best Practices

- **Never use for actual sensitive communications**
- Always combine multiple layers (PQC + classical crypto)
- Implement proper key lifecycle (generation → use → rotation → destruction)
- Use hardware RNGs in production (not simulated QRNG)
- Follow NIST PQC migration guidelines
- Regular security updates for all dependencies

### Threat Model

**Protected Against**:
- Harvest-now-decrypt-later quantum attacks
- Shor's algorithm (via PQC)
- Grover's algorithm (via 256-bit security levels)
- Passive eavesdropping (via QKD detection)

**NOT Protected Against**:
- Side-channel attacks (timing, power, EM)
- Supply chain attacks on dependencies
- Malware on endpoints
- Social engineering
- Physical access to systems

## Contributing

Contributions welcome! This is an educational project, so focus on:

- **Code Clarity**: Prioritize readability over optimization
- **Documentation**: Explain the "why" not just the "how"
- **Educational Value**: Include comments teaching quantum/crypto concepts
- **Testing**: Every feature needs tests

### Contribution Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/qkd-e91-protocol`
3. Implement with tests and docs
4. Run full test suite: `pytest tests/`
5. Run linters: `black . && flake8 . && bandit -r qsecure/`
6. Submit PR with detailed description

### Code Style

- **Python**: PEP 8, Black formatter
- **Docstrings**: Google style
- **Type Hints**: Required for all functions
- **Comments**: Explain quantum/crypto concepts inline

## References

### Primary Source
- SIPRI (Stockholm International Peace Research Institute). *Military and Security Dimensions of Quantum Technologies: A Primer*. Michal Krelina, July 2025. DOI: 10.55163/ZVTL1529.

### Post-Quantum Cryptography
- NIST. *NIST Releases First 3 Finalized Post-Quantum Encryption Standards*. August 13, 2024.
- NIST FIPS 203 (CRYSTALS-Kyber), FIPS 204 (CRYSTALS-Dilithium), FIPS 205 (SPHINCS+).

### Quantum Key Distribution
- C. H. Bennett and G. Brassard. *Quantum cryptography: Public key distribution and coin tossing*. Proceedings of IEEE International Conference on Computers, Systems and Signal Processing, 1984.
- A. K. Ekert. *Quantum cryptography based on Bell's theorem*. Physical Review Letters, 1991.

### Quantum Computing
- IBM Qiskit Documentation: https://qiskit.org/documentation/
- M. A. Nielsen and I. L. Chuang. *Quantum Computation and Quantum Information*. Cambridge University Press, 2010.

### Security Standards
- German BSI. *Status of Quantum Computer Development*. Version 2.1, August 2024.
- ETSI GR QKD 007 (QKD implementations).

## License

This project is licensed under the **MIT License** - see LICENSE file for details.

**Disclaimer**: This is educational software. Not intended for protecting real sensitive information. No warranty provided. Use at your own risk.

---

## Quick Start Example

```python
# examples/quickstart.py
from qsecure import QRNG, BB84, Kyber, HybridChannel

# 1. Generate quantum random key
qrng = QRNG(backend='qasm_simulator')
random_bytes = qrng.generate(32)  # 256 bits

# 2. QKD between Alice and Bob
alice = BB84.Alice()
bob = BB84.Bob()
qkd_key = alice.exchange_key(bob, n_qubits=1024)

# 3. PQC key encapsulation
kyber = Kyber(security_level=1024)
pk, sk = kyber.keypair()
ct, ss = kyber.encapsulate(pk)

# 4. Hybrid encryption
channel = HybridChannel(qkd_key=qkd_key, pqc_key=ss)
ciphertext = channel.encrypt(b"Quantum-secure message")
plaintext = channel.decrypt(ciphertext)

print("Success! Message:", plaintext)
```

Run: `python examples/quickstart.py`

---

**Built with ❤️ for the quantum-secure future**

*"The goal is not to control quantum's development, but to ensure that it strengthens rather than destabilizes global peace and security."* - SIPRI 2025