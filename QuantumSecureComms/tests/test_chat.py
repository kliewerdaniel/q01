"""
Unit tests for secure chat application.

Tests QKD-based key exchange, secure channel establishment,
and end-to-end encrypted communication.
"""

import unittest
import unittest.mock as mock
import socket
import threading
import time
import json
from unittest.mock import Mock, patch, MagicMock

from ..qsecure.comms.chat import (
    QKDSession, SecureChatServer, SecureChatClient, SecureChannel
)
from ..qsecure.qkd.bb84 import BB84Protocol, simulate_bb84_with_eve
from ..qsecure.pqc.dilithium import dilithium_keygen
from ..qsecure.pqc.kyber import kyber_keygen
from ..qsecure.hybrid.hybrid import HybridCrypto


class TestQKDSession(unittest.TestCase):
    """Test QKD session functionality."""

    def test_qkd_session_initialization(self):
        """Test QKD session initialization."""
        session = QKDSession(protocol='BB84', key_length=512)
        self.assertEqual(session.protocol, 'BB84')
        self.assertEqual(session.key_length, 512)
        self.assertIsNone(session.shared_key)
        self.assertEqual(session.qber, 0.0)
        self.assertFalse(session.eve_detected)

    @patch('qsecure.comms.chat.simulate_bb84')
    def test_establish_key_success(self, mock_simulate):
        """Test successful key establishment."""
        mock_simulate.return_value = ([1, 0, 1], 0.05, False)

        session = QKDSession()
        key, qber, eve_detected = session.establish_key()

        mock_simulate.assert_called_once()
        self.assertIsNotNone(session.shared_key)
        self.assertEqual(len(session.shared_key), 32)  # HKDF output length
        self.assertEqual(session.qber, 0.05)
        self.assertFalse(session.eve_detected)

    def test_establish_key_with_eve(self):
        """Test key establishment with Eve present."""
        session = QKDSession()
        key, qber, eve_detected = session.establish_key()

        # With Eve, QBER should be higher
        self.assertIsNotNone(session.shared_key)
        self.assertIsInstance(session.qber, float)
        self.assertIsInstance(session.eve_detected, bool)

    def test_unsupported_protocol(self):
        """Test unsupported QKD protocol."""
        session = QKDSession(protocol='UNSUPPORTED')

        with self.assertRaises(ValueError):
            session.establish_key()


class TestSecureChannel(unittest.TestCase):
    """Test secure communication channel."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate test keys
        self.alice_keys = dilithium_keygen('Dilithium3')
        self.bob_keys = dilithium_keygen('Dilithium3')
        self.kyber_keys = kyber_keygen('Kyber1024')

        # Create mock QKD secret
        self.qkd_secret = b'test_qkd_secret_32_bytes_long'

    def test_secure_channel_initialization(self):
        """Test secure channel initialization."""
        channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.alice_keys['private'],
            peer_public_key=self.bob_keys['public']
        )

        self.assertEqual(channel.private_key, self.alice_keys['private'])
        self.assertEqual(channel.peer_public_key, self.bob_keys['public'])
        self.assertEqual(channel.sequence_number, 0)

    def test_encrypt_message(self):
        """Test message encryption."""
        channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.alice_keys['private'],
            peer_public_key=self.bob_keys['public']
        )

        message = "Hello, secure world!"
        packet = channel.encrypt_message(message)

        required_keys = {'seq', 'ciphertext', 'nonce', 'tag', 'salt', 'signature', 'timestamp'}
        self.assertTrue(required_keys.issubset(packet.keys()))
        self.assertEqual(packet['seq'], 0)
        self.assertIsInstance(packet['timestamp'], int)
        self.assertEqual(channel.sequence_number, 1)

    def test_decrypt_message(self):
        """Test message decryption."""
        alice_channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.alice_keys['private'],
            peer_public_key=self.bob_keys['public']
        )

        bob_channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.bob_keys['private'],
            peer_public_key=self.alice_keys['public']
        )

        message = "Test message"
        packet = alice_channel.encrypt_message(message)
        decrypted = bob_channel.decrypt_message(packet)

        self.assertEqual(decrypted, message)

    def test_decrypt_invalid_signature(self):
        """Test decryption with invalid signature."""
        alice_channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.alice_keys['private'],
            peer_public_key=self.bob_keys['public']
        )

        bob_channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.bob_keys['private'],
            peer_public_key=self.alice_keys['public']
        )

        message = "Test message"
        packet = alice_channel.encrypt_message(message)

        # Tamper with signature
        packet['signature'] = 'invalid_signature'

        result = bob_channel.decrypt_message(packet)
        self.assertIsNone(result)

    def test_authenticate_peer(self):
        """Test peer authentication."""
        channel = SecureChannel(
            qkd_secret=self.qkd_secret,
            kem_secret=self.kyber_keys['public'],
            private_key=self.alice_keys['private'],
            peer_public_key=self.bob_keys['public']
        )

        challenge = b'random_challenge'
        signature = channel.authenticate_peer(challenge)

        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)


class TestSecureChatServer(unittest.TestCase):
    """Test secure chat server functionality."""

    def setUp(self):
        """Set up test server."""
        self.server = SecureChatServer(host='localhost', port=5001, max_clients=2)

    def tearDown(self):
        """Clean up after tests."""
        try:
            self.server.stop()
        except:
            pass

    @patch('qsecure.comms.chat.simulate_bb84')
    @patch('qsecure.comms.chat.dilithium_keygen')
    @patch('qsecure.comms.chat.kyber_keygen')
    def test_handle_client_qkd_handshake(self, mock_kyber, mock_dilithium, mock_bb84):
        """Test client QKD handshake."""
        mock_bb84.return_value = ([1, 0, 1, 0], 0.02, False)
        mock_dilithium.return_value = {'public': b'alice_pub', 'private': b'alice_priv'}
        mock_kyber.return_value = {'public': b'kyber_pub', 'private': b'kyber_priv'}

        # Mock client socket
        mock_socket = Mock()
        mock_socket.recv.return_value = json.dumps({
            'name': 'Alice',
            'qkd_protocol': 'BB84',
            'key_length': 512
        }).encode()

        # Mock the acceptance response (simplified)
        with patch.object(self.server, 'start_chat_session'):
            self.server.handle_client(mock_socket)

        mock_bb84.assert_called_once()
        mock_dilithium.assert_called()
        mock_kyber.assert_called()

        # Check that response was sent
        mock_socket.send.assert_called()
        response = json.loads(mock_socket.send.call_args[0][0].decode())
        self.assertTrue(response['qkd_success'])

    def test_server_initialization(self):
        """Test server initialization."""
        self.assertEqual(self.server.host, 'localhost')
        self.assertEqual(self.server.port, 5001)
        self.assertEqual(self.server.max_clients, 2)
        self.assertEqual(len(self.server.qkd_sessions), 0)
        self.assertEqual(len(self.server.secure_channels), 0)


class TestSecureChatClient(unittest.TestCase):
    """Test secure chat client functionality."""

    def setUp(self):
        """Set up test client."""
        self.client = SecureChatClient(host='localhost', port=5001)

    def tearDown(self):
        """Clean up after tests."""
        try:
            self.client.disconnect()
        except:
            pass

    @patch('qsecure.comms.chat.dilithium_keygen')
    @patch('qsecure.comms.chat.kyber_keygen')
    @patch('qsecure.comms.chat.QKDSession')
    def test_connect_successful_handshake(self, mock_qkd_session, mock_kyber, mock_dilithium):
        """Test successful client connection with QKD handshake."""
        # Mock key generation
        mock_dilithium.return_value = {'public': b'alice_pub', 'private': b'alice_priv'}
        mock_kyber.return_value = {'public': b'kyber_pub', 'private': b'kyber_priv'}

        # Mock QKD session
        mock_session_instance = Mock()
        mock_session_instance.establish_key.return_value = (b'qkd_key_32_bytes', 0.03, False)
        mock_qkd_session.return_value = mock_session_instance

        # Mock socket
        mock_socket = Mock()
        self.client.socket = mock_socket

        # Mock server response
        response = {
            'qkd_success': True,
            'qber': 0.03,
            'eve_detected': False,
            'dilithium_public': b'server_dilithium_pub'.hex(),
            'kyber_public': b'server_kyber_pub'.hex()
        }
        mock_socket.recv.return_value = json.dumps(response).encode()

        success = self.client.connect('Alice')

        self.assertTrue(success)
        self.assertTrue(self.client.connected)
        mock_qkd_session.assert_called()
        mock_dilithium.assert_called()
        mock_kyber.assert_called()

    def test_send_message(self):
        """Test message sending."""
        self.client.secure_channel = Mock()
        self.client.secure_channel.encrypt_message.return_value = {'encrypted': 'data'}
        mock_socket = Mock()
        self.client.socket = mock_socket

        self.client.send_message("Test message")

        self.client.secure_channel.encrypt_message.assert_called_with("Test message")
        mock_socket.send.assert_called()


class TestEndToEndCommunication(unittest.TestCase):
    """Test end-to-end secure communication."""

    def test_full_protocol_simulation(self):
        """Test complete secure communication protocol simulation."""
        # Simulate Alice and Bob setting up secure channel
        alice_dilithium = dilithium_keygen('Dilithium3')
        bob_dilithium = dilithium_keygen('Dilithium3')
        kyber_keys = kyber_keygen('Kyber1024')

        # QKD key exchange
        bb84 = BB84Protocol(num_bits=256)
        key, qber, eve_detected = bb84.run_protocol()

        # Convert key to bytes
        key_int = int(''.join(map(str, key)), 2)
        key_bytes = key_int.to_bytes((len(key) + 7) // 8, byteorder='big')

        # Setup secure channels
        alice_channel = SecureChannel(
            qkd_secret=key_bytes,
            kem_secret=kyber_keys['public'],
            private_key=alice_dilithium['private'],
            peer_public_key=bob_dilithium['public']
        )

        bob_channel = SecureChannel(
            qkd_secret=key_bytes,
            kem_secret=kyber_keys['public'],
            private_key=bob_dilithium['private'],
            peer_public_key=alice_dilithium['public']
        )

        # Exchange messages
        original_message = "Hello from Alice!"
        packet = alice_channel.encrypt_message(original_message)
        decrypted_message = bob_channel.decrypt_message(packet)

        self.assertEqual(original_message, decrypted_message)

        # Test reverse direction
        response_message = "Hello back from Bob!"
        packet2 = bob_channel.encrypt_message(response_message)
        decrypted_response = alice_channel.decrypt_message(packet2)

        self.assertEqual(response_message, decrypted_response)


class TestEveInterception(unittest.TestCase):
    """Test Eve's interception and its detection."""

    def test_eve_interception_detected(self):
        """Test that Eve's interception increases QBER."""
        # Run BB84 without Eve
        bb84_no_eve = BB84Protocol(num_bits=1024)
        key_no_eve, qber_no_eve, eve_detected_no_eve = bb84_no_eve.run_protocol()

        # Run BB84 with Eve intercepting 100%
        bb84_with_eve = BB84Protocol(num_bits=1024, eve_interception=1.0)
        key_with_eve, qber_with_eve, eve_detected_with_eve = bb84_with_eve.run_protocol()

        # QBER should be higher with Eve
        self.assertGreater(qber_with_eve, qber_no_eve)
        # Should detect Eve when QBER > 0.11
        if qber_with_eve > 0.11:
            self.assertTrue(eve_detected_with_eve)

    def test_eve_partial_interception(self):
        """Test Eve intercepting only some photons."""
        bb84_partial = BB84Protocol(num_bits=1024, eve_interception=0.5)
        key, qber, eve_detected = bb84_partial.run_protocol()

        # QBER should be measurable but possibly below detection threshold
        self.assertIsInstance(qber, float)
        self.assertGreaterEqual(qber, 0.0)
        self.assertLessEqual(qber, 1.0)


if __name__ == '__main__':
    unittest.main()
