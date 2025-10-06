"""
Quantum Random Number Generation (QRNG) using Qiskit.

This module simulates quantum randomness by measuring qubits in superposition.
It includes von Neumann debiasing to remove biases and entropy estimation.
"""

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)

class QuantumRNG:
    """
    Simulates quantum random number generation using Qiskit Aer backend.
    
    Generates random bits by measuring qubits initialized in superposition.
    Applies von Neumann debiasing for post-processing.
    """
    
    def __init__(self, backend=AerSimulator()):
        """
        Initialize QRNG with specified backend.
        
        Args:
            backend: Qiskit backend for quantum simulation (default: AerSimulator)
        """
        self.backend = backend
        
    def generate_raw_bits(self, num_bits: int) -> List[int]:
        """
        Generate raw random bits from quantum measurements.
        
        Uses Hadamard gates to put qubits in superposition, then measures.
        For each bit, create a single qubit circuit.
        
        Args:
            num_bits (int): Number of random bits to generate
            
        Returns:
            List[int]: List of 0s and 1s
        """
        bits = []
        # For educational purposes, generate bits one by one
        # In practice, group for efficiency
        for _ in range(num_bits):
            qc = QuantumCircuit(1, 1)  # 1 qubit, 1 classical bit
            qc.h(0)  # Hadamard gate for superposition
            qc.measure(0, 0)
            
            job = self.backend.run(qc, shots=1)
            result = job.result()
            counts = result.get_counts(qc)
            
            # Get the measurement outcome (0 or 1)
            bit = int(list(counts.keys())[0][0])
            bits.append(bit)
            
        logger.info(f"Generated {num_bits} raw random bits")
        return bits
    
    def von_neumann_debias(self, raw_bits: List[int]) -> List[int]:
        """
        Apply von Neumann debiasing algorithm.
        
        Converts pairs of bits (00->1, 11->0, 01->left bit, 10->invert) 
        to reduce bias in quantum measurements.
        
        Args:
            raw_bits (List[int]): Raw bit sequence
            
        Returns:
            List[int]: Debiasing bits
        """
        debiased = []
        i = 0
        while i < len(raw_bits) - 1:
            pair = str(raw_bits[i]) + str(raw_bits[i+1])
            if pair == '01':
                debiased.append(1)
            elif pair == '10':
                debiased.append(0)
            # Discard 00 and 11
            i += 2
            
        logger.info(f"Von Neumann debiased: {len(raw_bits)} -> {len(debiased)} bits")
        return debiased
        
    def estimate_entropy(self, bits: List[int]) -> float:
        """
        Estimate Shannon entropy of bit sequence.
        
        Entropy H = -sum(p_i * log2(p_i)) for i in {0,1}
        
        Args:
            bits (List[int]): Bit sequence
            
        Returns:
            float: Entropy in bits
        """
        if not bits:
            return 0.0
            
        freq_0 = bits.count(0) / len(bits)
        freq_1 = bits.count(1) / len(bits)
        
        entropy = 0.0
        for freq in [freq_0, freq_1]:
            if freq > 0:
                entropy -= freq * np.log2(freq)
                
        return entropy
        
    def generate_random_bits(self, num_bits: int, explain: bool = False) -> Tuple[List[int], float]:
        """
        Generate random bits with debiasing and entropy computation.
        
        Args:
            num_bits (int): Desired output bits
            explain (bool): If True, print step-by-step explanations
            
        Returns:
            Tuple[List[int], float]: Final bits and their entropy
        """
        if explain:
            print("=== QRNG Generation Process ===")
            print("Phase 1: Quantum Measurement")
            print("Each qubit is put in superposition (|0> + |1>)/√2")
            print("Measurement collapses to 0 or 1 with equal probability")
            
        # Generate extra bits since debiasing reduces count
        raw_count = int(num_bits * 2.5)  # Rough estimate for debiasing
        raw_bits = self.generate_raw_bits(raw_count)
        
        if explain:
            print(f"Generated {len(raw_bits)} raw bits")
            print(f"Sample raw bits: {raw_bits[:10]}")
            
        debiased_bits = self.von_neumann_debias(raw_bits)
        
        if explain:
            print("Phase 2: Von Neumann Basis Choice Pairing")
            print("Pairs: 01 -> 1, 10 -> 0, discard 00/11")
            print(f"After debiasing: {len(debiased_bits)} bits")
            
        # Take only requested number
        final_bits = debiased_bits[:num_bits]
        
        entropy = self.estimate_entropy(final_bits)
        
        if explain:
            print("Phase 3: Entropy Validation")
            print(f"Entropy: {entropy:.2f}")
            print("Expected entropy ~ 1.0 bit for perfect randomness")
            print(f"Final bits: {final_bits}")

        return final_bits, entropy

def generate_random_bits(num_bits: int, explain: bool = False) -> Tuple[List[int], float]:
    """
    Convenience function for generating random bits using QuantumRNG.

    Args:
        num_bits (int): Number of random bits to generate
        explain (bool): If True, print step-by-step explanations

    Returns:
        Tuple[List[int], float]: Final bits and their entropy
    """
    qrng = QuantumRNG()
    return qrng.generate_random_bits(num_bits, explain)
