"""
Unit tests for BB84 Quantum Key Distribution protocol.

Tests key generation, basis reconciliation, QBER calculation,
and Eve's interception simulation.
"""

import unittest
from unittest.mock import Mock, patch

try:
    # Try relative imports first
    from ..qsecure.qkd.bb84 import (
        Alice, Bob, Eve, BB84Protocol,
        simulate_bb84, simulate_bb84_with_eve
    )
except ImportError:
    # Fall back to absolute imports for direct execution
    from qsecure.qkd.bb84 import (
        Alice, Bob, Eve, BB84Protocol,
        simulate_bb84, simulate_bb84_with_eve
    )


class TestAlice(unittest.TestCase):
    """Test Alice's BB84 role."""

    def test_alice_initialization(self):
        """Test Alice initialization."""
        alice = Alice(num_bits=256)
        self.assertEqual(len(alice.bits), 256)
        self.assertEqual(len(alice.bases), 256)
        self.assertEqual(len(alice.polarizations), 0)  # Not yet encoded

    def test_generate_bits_and_bases(self):
        """Test bit and basis generation."""
        alice = Alice(num_bits=100)
        alice.generate_bits_and_bases()

        self.assertEqual(len(alice.bits), 100)
        self.assertEqual(len(alice.bases), 100)
        self.assertEqual(len(alice.polarizations), 100)

        # All bits should be 0 or 1
        self.assertTrue(all(bit in [0, 1] for bit in alice.bits))
        # All bases should be '+' or 'x'
        self.assertTrue(all(basis in ['+', 'x'] for basis in alice.bases))
        # All polarizations should be valid photon states
        valid_polarizations = ['H', 'V', 'D', 'A']
        self.assertTrue(all(pol in valid_polarizations for pol in alice.polarizations))

    def test_polarization_encoding(self):
        """Test bit to polarization encoding."""
        alice = Alice(num_bits=4)
        alice.bits = [0, 1, 0, 1]  # Override random bits
        alice.bases = ['+', '+', 'x', 'x']
        alice._encode_polarizations()

        # + basis: 0->H, 1->V
        self.assertEqual(alice.polarizations[0], 'H')  # bit 0, + basis
        self.assertEqual(alice.polarizations[1], 'V')  # bit 1, + basis
        # x basis: 0->D, 1->A
        self.assertEqual(alice.polarizations[2], 'D')  # bit 0, x basis
        self.assertEqual(alice.polarizations[3], 'A')  # bit 1, x basis


class TestBob(unittest.TestCase):
    """Test Bob's BB84 role."""

    def test_bob_initialization(self):
        """Test Bob initialization."""
        bob = Bob(num_bits=256)
        self.assertEqual(len(bob.bases), 0)  # Not yet chosen
        self.assertEqual(len(bob.measurements), 0)  # Not yet measured

    def test_choose_measurement_bases(self):
        """Test basis selection."""
        bob = Bob(num_bits=100)
        bob.choose_measurement_bases()

        self.assertEqual(len(bob.bases), 100)
        # All bases should be '+' or 'x'
        self.assertTrue(all(basis in ['+', 'x'] for basis in bob.bases))

    def test_measure_photons_matching_bases(self):
        """Test measurement with matching bases."""
        alice = Alice(num_bits=10)
        alice.bits = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        alice.bases = ['+', '+', '+', '+', '+', 'x', 'x', 'x', 'x', 'x']
        alice._encode_polarizations()

        # Bob chooses same bases as Alice
        bob = Bob(num_bits=10)
        bob.bases = alice.bases.copy()

        bob.measure_photons(alice)

        # When bases match, measurement should equal Alice's original bit
        self.assertEqual(bob.measurements, alice.bits)

    def test_measure_photons_mismatching_bases(self):
        """Test measurement with mismatching bases."""
        alice = Alice(num_bits=10)
        alice.bits = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        alice.bases = ['+', '+', '+', '+', '+', 'x', 'x', 'x', 'x', 'x']
        alice._encode_polarizations()

        # Bob chooses different bases
        bob = Bob(num_bits=10)
        bob.bases = ['x', 'x', 'x', 'x', 'x', '+', '+', '+', '+', '+']

        bob.measure_photons(alice)

        # When bases mismatch, measurements should be random
        self.assertEqual(len(bob.measurements), 10)
        # We can't predict random results, just check they're valid bits
        self.assertTrue(all(bit in [0, 1] for bit in bob.measurements))


class TestEve(unittest.TestCase):
    """Test Eve's interception role."""

    def test_eve_initialization(self):
        """Test Eve initialization."""
        eve = Eve(interception_probability=0.5)
        self.assertEqual(eve.interception_probability, 0.5)
        self.assertEqual(eve.intercepted_count, 0)

    def test_eve_full_interception(self):
        """Test Eve intercepting all photons."""
        alice = Alice(num_bits=20)
        alice.generate_bits_and_bases()

        eve = Eve(interception_probability=1.0)
        intercepted_polarizations = eve.intercept_photons(alice, explain=False)

        self.assertEqual(len(intercepted_polarizations), 20)
        self.assertEqual(eve.intercepted_count, 20)
        self.assertEqual(len(eve.bases), 20)
        self.assertEqual(len(eve.measurements), 20)

    def test_eve_no_interception(self):
        """Test Eve not intercepting any photons."""
        alice = Alice(num_bits=20)
        alice.generate_bits_and_bases()

        eve = Eve(interception_probability=0.0)
        intercepted_polarizations = eve.intercept_photons(alice, explain=False)

        # Should return original polarizations unchanged
        self.assertEqual(intercepted_polarizations, alice.polarizations)
        self.assertEqual(eve.intercepted_count, 0)
        self.assertEqual(len(eve.bases), 20)  # None for each position
        self.assertEqual(len(eve.measurements), 20)  # None for each position

    def test_eve_partial_interception(self):
        """Test Eve intercepting 50% of photons."""
        alice = Alice(num_bits=100)
        alice.generate_bits_and_bases()

        eve = Eve(interception_probability=0.5)
        intercepted_polarizations = eve.intercept_photons(alice, explain=False)

        self.assertEqual(len(intercepted_polarizations), 100)
        # Should intercept approximately 50 photons (with some variance)
        self.assertTrue(40 <= eve.intercepted_count <= 60)


class TestBB84Protocol(unittest.TestCase):
    """Test complete BB84 protocol."""

    def test_bb84_initialization_no_eve(self):
        """Test BB84 initialization without Eve."""
        protocol = BB84Protocol(num_bits=512)
        self.assertIsNotNone(protocol.alice)
        self.assertIsNotNone(protocol.bob)
        self.assertIsNone(protocol.eve)
        self.assertEqual(protocol.num_bits, 512)

    def test_bb84_initialization_with_eve(self):
        """Test BB84 initialization with Eve."""
        protocol = BB84Protocol(num_bits=512, eve_interception=0.3)
        self.assertIsNotNone(protocol.alice)
        self.assertIsNotNone(protocol.bob)
        self.assertIsNotNone(protocol.eve)
        self.assertEqual(protocol.eve.interception_probability, 0.3)

    def test_bb84_run_protocol_no_eve(self):
        """Test complete BB84 protocol without Eve."""
        protocol = BB84Protocol(num_bits=256)
        key, qber, eve_detected = protocol.run_protocol(explain=False)

        self.assertIsInstance(key, list)
        self.assertGreater(len(key), 0)
        self.assertTrue(all(bit in [0, 1] for bit in key))
        self.assertIsInstance(qber, float)
        self.assertGreaterEqual(qber, 0.0)
        self.assertLessEqual(qber, 1.0)
        # Should typically be low QBER without Eve
        self.assertLess(qber, 0.05)

    def test_bb84_run_protocol_with_eve(self):
        """Test complete BB84 protocol with Eve."""
        protocol = BB84Protocol(num_bits=256, eve_interception=1.0)
        key, qber, eve_detected = protocol.run_protocol(explain=False)

        self.assertIsInstance(key, list)
        self.assertGreater(len(key), 0)
        self.assertIsInstance(qber, float)
        self.assertIsInstance(eve_detected, bool)
        # With full interception, QBER should be high
        self.assertGreater(qber, 0.5)

    def test_bb84_basis_reconciliation(self):
        """Test basis reconciliation phase."""
        protocol = BB84Protocol(num_bits=100)
        protocol.alice.generate_bits_and_bases()
        protocol.bob.choose_measurement_bases()
        protocol.bob.measure_photons(protocol.alice)

        protocol.reconcile_bases()

        # Should find matching indices
        self.assertGreater(len(protocol.matching_indices), 0)
        # All matching indices should have same bases
        for idx in protocol.matching_indices:
            self.assertEqual(protocol.alice.bases[idx], protocol.bob.bases[idx])

    def test_bb84_error_estimation(self):
        """Test QBER calculation."""
        protocol = BB84Protocol(num_bits=100)
        protocol.alice.generate_bits_and_bases()
        protocol.bob.choose_measurement_bases()
        protocol.bob.measure_photons(protocol.alice)
        protocol.reconcile_bases()

        protocol.estimate_errors()

        self.assertIsInstance(protocol.qber, float)
        self.assertGreaterEqual(protocol.qber, 0.0)
        self.assertLessEqual(protocol.qber, 1.0)

    def test_simulate_bb84_function(self):
        """Test convenience function."""
        key, qber, eve_detected = simulate_bb84(num_bits=128)

        self.assertIsInstance(key, list)
        self.assertGreater(len(key), 0)
        self.assertIsInstance(qber, float)
        self.assertIsInstance(eve_detected, bool)

    def test_simulate_bb84_with_eve_function(self):
        """Test convenience function with Eve."""
        key, qber, eve_detected = simulate_bb84_with_eve(num_bits=128, eve_interception=0.5)

        self.assertIsInstance(key, list)
        self.assertGreater(len(key), 0)
        self.assertIsInstance(qber, float)
        self.assertIsInstance(eve_detected, bool)


class TestBB84Statistics(unittest.TestCase):
    """Statistical tests for BB84 protocol."""

    def test_qber_distribution_no_eve(self):
        """Test QBER distribution without Eve (should be very low)."""
        qbers = []
        for _ in range(10):
            _, qber, _ = simulate_bb84(num_bits=512)
            qbers.append(qber)

        avg_qber = sum(qbers) / len(qbers)
        # Without Eve, average QBER should be very low (< 5%)
        self.assertLess(avg_qber, 0.05)

    def test_qber_distribution_with_eve(self):
        """Test QBER distribution with Eve (should be high when intercepting)."""
        qbers_full = []
        qbers_half = []

        for _ in range(5):
            _, qber_full, _ = simulate_bb84_with_eve(num_bits=512, eve_interception=1.0)
            _, qber_half, _ = simulate_bb84_with_eve(num_bits=512, eve_interception=0.5)
            qbers_full.append(qber_full)
            qbers_half.append(qber_half)

        avg_qber_full = sum(qbers_full) / len(qbers_full)
        avg_qber_half = sum(qbers_half) / len(qbers_half)

        # Full interception should have very high QBER
        self.assertGreater(avg_qber_full, 0.4)
        # Half interception should have moderate QBER
        self.assertTrue(0.15 <= avg_qber_half <= 0.35)

    def test_key_length_distribution(self):
        """Test that key length varies due to basis reconciliation."""
        key_lengths = []
        for _ in range(20):
            key, _, _ = simulate_bb84(num_bits=512)
            key_lengths.append(len(key))

        # Key length should vary due to random basis choices
        # (approximately half the photons should have matching bases)
        min_length = min(key_lengths)
        max_length = max(key_lengths)

        self.assertGreater(max_length - min_length, 20)  # Some variation

        avg_length = sum(key_lengths) / len(key_lengths)
        # Should be roughly half of input bits
        self.assertTrue(200 <= avg_length <= 300)


if __name__ == '__main__':
    unittest.main()
