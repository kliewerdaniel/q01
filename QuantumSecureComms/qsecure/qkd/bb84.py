"""
BB84 Quantum Key Distribution Protocol Implementation

This module simulates the BB84 protocol where Alice encodes bits into photon polarizations
in randomly chosen bases, and Bob measures in randomly chosen bases. Basis reconciliation
reveals matching measurements, and QBER (Quantum Bit Error Rate) detects eavesdropping.
"""

import random
from typing import List, Tuple, Optional
import numpy as np
import logging

logger = logging.getLogger(__name__)

class Alice:
    """
    Alice's BB84 role: generates random bits and bases, encodes into photon states.
    
    In BB84, Alice chooses random bit (0/1) and basis (+ or x).
    For photons: + basis = horizontal/vertical (0°/90°), x basis = diagonal (45°/135°).
    """
    
    def __init__(self, num_bits: int = 1024):
        """
        Initialize Alice with desired number of bits.
        
        Args:
            num_bits (int): Number of bits to transmit
        """
        self.num_bits = num_bits
        self.bits: List[int] = []
        self.bases: List[str] = []
        self.polarizations: List[str] = []
        
    def generate_bits_and_bases(self, explain: bool = False) -> None:
        """
        Generate random bits and random bases for encoding.
        
        For each bit, choose 0/1 uniformly, and basis '+' or 'x' uniformly.
        
        Args:
            explain (bool): Print explanations
        """
        if explain:
            print("=== Alice's Encoding ===")
            print("Alice chooses random bits and encoding bases:")
            print("- Bit 0: |0⟩, Bit 1: |1⟩ (photon polarizations)")
            print("- Basis +: Horizontal/Vertical (rectilinear)")
            print("- Basis x: Diagonal polarizations")
            
        self.bits = [random.randint(0, 1) for _ in range(self.num_bits)]
        self.bases = [random.choice(['+', 'x']) for _ in range(self.num_bits)]
        
        self._encode_polarizations()
        
        if explain:
            print(f"Generated {self.num_bits} bits and bases")
            print(f"Sample bits: {self.bits[:10]}")
            print(f"Sample bases: {self.bases[:10]}")
        
    def _encode_polarizations(self) -> None:
        """
        Map bits and bases to polarization states.
        
        + basis: 0->0° (horizontal), 1->90° (vertical)
        x basis: 0->45°, 1->135° (diagonal)
        """
        polarizations = []
        for bit, basis in zip(self.bits, self.bases):
            if basis == '+':
                polar = 'H' if bit == 0 else 'V'  # Horizontal or Vertical
            else:  # x basis
                polar = 'D' if bit == 0 else 'A'  # Diagonal or Anti-diagonal
            polarizations.append(polar)
        self.polarizations = polarizations

class Bob:
    """
    Bob's BB84 role: chooses random measurement bases and measures photons.
    
    Bob doesn't know Alice's bases, only his own random choice.
    """
    
    def __init__(self, num_bits: int = 1024):
        """
        Initialize Bob with expected number of bits.
        
        Args:
            num_bits (int): Expected number of received photons
        """
        self.num_bits = num_bits
        self.bases: List[str] = []
        self.measurements: List[int] = []
        
    def choose_measurement_bases(self, explain: bool = False) -> None:
        """
        Bob randomly chooses measurement bases.
        
        He doesn't know Alice's bases, so he guesses uniformly.
        
        Args:
            explain (bool): Print explanations
        """
        if explain:
            print("\n=== Bob's Measurement ===")
            print("Bob randomly chooses measurement bases:")
            print("- Independent of Alice - only 50% chance to match")
            
        self.bases = [random.choice(['+', 'x']) for _ in range(self.num_bits)]
        
        if explain:
            print(f"Bob's bases: {self.bases[:10]}")
            
    def measure_photons(self, alice: Alice, explain: bool = False) -> None:
        """
        Measure photons using chosen bases.
        
        If Bob's basis matches Alice's, measurement gives correct bit.
        If mismatch, measurement is random.
        
        Args:
            alice (Alice): Alice's transmission data
            explain (bool): Print explanations
        """
        measurements = []
        for i, (polar, bob_basis) in enumerate(zip(alice.polarizations, self.bases)):
            alice_basis = alice.bases[i]
            
            if bob_basis == alice_basis:
                # Matching basis: correct bit
                bit = alice.bits[i]
            else:
                # Mismatching basis: random result
                bit = random.randint(0, 1)
                
            measurements.append(bit)
            
        self.measurements = measurements
        
        if explain:
            print(f"Bob's measurements: {measurements[:10]}")
            print("Where bases match: correct bit; mismatch: random flip")

class BB84Protocol:
    """
    Main BB84 QKD protocol simulation.
    
    Coordinates Alice and Bob's actions, performs basis reconciliation,
    and computes QBER to detect eavesdropping.
    """
    
    def __init__(self, num_bits: int = 1024):
        """
        Initialize BB84 protocol with key length.
        
        Args:
            num_bits (int): Desired key length
        """
        self.num_bits = num_bits
        self.alice = Alice(num_bits)
        self.bob = Bob(num_bits)
        self.matching_indices: List[int] = []
        self.final_key: List[int] = []
        self.qber: float = 0.0
        self.eve_detected = False
        
    def run_protocol(self, explain: bool = False) -> Tuple[List[int], float, bool]:
        """
        Execute complete BB84 protocol.
        
        Args:
            explain (bool): Enable step-by-step explanations
            
        Returns:
            Tuple[List[int], float, bool]: (key, qber, eve_detected)
        """
        if explain:
            print("========== BB84 Quantum Key Distribution ==========")
            
        # Phase 1: Alice encodes
        self.alice.generate_bits_and_bases(explain)
        
        # Phase 2: Bob measures
        self.bob.choose_measurement_bases(explain)
        self.bob.measure_photons(self.alice, explain)
        
        # Phase 3: Basis reconciliation (public channel)
        self.reconcile_bases(explain)
        
        # Phase 4: Error estimation (QBER calculation)
        self.estimate_errors(explain)
        
        # Test for eavesdropping
        self.eve_detected = self.qber > 0.11  # Threshold ~10%
        
        if explain:
            print(f"\nEavesdropping detection: {'YES' if self.eve_detected else 'NO'}")
            
        return self.final_key, self.qber, self.eve_detected
    
    def reconcile_bases(self, explain: bool = False) -> None:
        """
        Publicly compare bases to find matching measurements.
        
        Alice and Bob announce bases over public channel (not bits).
        
        Args:
            explain (bool): Print explanations
        """
        if explain:
            print("\n=== Basis Reconciliation ===")
            print("Alice and Bob announce measurement bases publicly:")
            print("- Matching bases: keep measurements")
            print("- Mismatching: discard measurements")
            
        matching_indices = []
        for i in range(self.num_bits):
            if self.alice.bases[i] == self.bob.bases[i]:
                matching_indices.append(i)
                
        self.matching_indices = matching_indices
        
        if explain:
            matches = len(matching_indices)
            print(f"Bases matched: {matches}/{self.num_bits}")
            print(f"Key length: {matches}")
            
        # Extract key bits from matching indices
        self.final_key = [self.alice.bits[i] for i in matching_indices]
        
        # Verify with Bob's measurements (should match)
        bob_key = [self.bob.measurements[i] for i in matching_indices]
        
        # Discard indices where Bob got error (mismatch gave wrong bit)
        # In real QKD, they'd error correct, but here for simplicity
        
    def estimate_errors(self, explain: bool = False) -> None:
        """
        Calculate Quantum Bit Error Rate (QBER).
        
        QBER = fraction of mismatched bits in sifted key.
        High QBER indicates eavesdropping.
        
        Args:
            explain (bool): Print explanations
        """
        if explain:
            print("\n=== QBER Calculation ===")
            print("QBER (Quantum Bit Error Rate) = errors / total bits")
            print("High QBER (>10%) indicates presence of Eve")
            
        if not self.final_key:
            self.qber = 0.0
            return
            
        errors = 0
        for i in self.matching_indices:
            if self.alice.bits[i] != self.bob.measurements[i]:
                errors += 1
                
        self.qber = errors / len(self.matching_indices)
        
        if explain:
            print(f"QBER: {self.qber:.3f} ({errors}/{len(self.matching_indices)})")

def simulate_bb84(num_bits: int = 1024, explain: bool = False) -> Tuple[List[int], float, bool]:
    """
    Convenience function to run BB84 simulation.
    
    Args:
        num_bits (int): Desired key length
        explain (bool): Enable explanations
        
    Returns:
        Tuple[List[int], float, bool]: (key, qber, eve_detected)
    """
    protocol = BB84Protocol(num_bits)
    return protocol.run_protocol(explain)
