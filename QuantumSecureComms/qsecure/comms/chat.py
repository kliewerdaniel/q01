"""
Secure Chat Application with QKD Key Exchange

This module implements a real-time secure chat application that uses QKD protocols
for initial key distribution and hybrid cryptography for secure messaging.
"""

import socket
import threading
import time
import json
import select
from typing import Dict, Any, Optional, Tuple, Callable
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from ..qkd.bb84 import simulate_bb84
from ..hybrid.hybrid import HybridCrypto
from ..pqc.dilithium import dilithium_keygen, dilithium_sign, dilithium_verify
from ..pqc.kyber import kyber_keygen
from ..comms.secure_channel import SecureChannel, ChatServer, ChatClient
from ..utils.logger import get_logger

logger = get_logger(__name__)

class QKDSession:
    """
    QKD Session Manager for secure key exchange in chat.
    """

    def __init__(self, protocol: str = 'BB84', key_length: int = 1024):
        """
        Initialize QKD session.

        Args:
            protocol (str): QKD protocol to use
            key_length (int): Desired key length in bits
        """
        self.protocol = protocol
        self.key_length = key_length
        self.shared_key: Optional[bytes] = None
        self.qber: float = 0.0
        self.eve_detected = False

    def establish_key(self, explain: bool = False) -> Tuple[bytes, float, bool]:
        """
        Perform QKD key exchange simulation.

        Args:
            explain (bool): Enable detailed output

        Returns:
            Tuple[bytes, float, bool]: (shared_key, qber, eve_detected)
        """
        if self.protocol == 'BB84':
            key_bits, qber, eve_detected = simulate_bb84(self.key_length, explain=explain)

            # Convert bits to bytes
            key_int = int(''.join(map(str, key_bits)), 2)
            key_bytes = key_int.to_bytes((len(key_bits) + 7) // 8, byteorder='big')

            # Use HKDF to derive final 32-byte key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'quantum-chat-key',
                backend=default_backend()
            )
            self.shared_key = hkdf.derive(key_bytes)
            self.qber = qber
            self.eve_detected = eve_detected

            logger.info(".2f")

        else:
            raise ValueError(f"Unsupported QKD protocol: {self.protocol}")

        return self.shared_key, self.qber, self.eve_detected

class SecureChatServer(ChatServer):
    """
    Enhanced chat server with QKD key exchange and end-to-end encryption.
    """

    def __init__(self, host='localhost', port=5000, max_clients=2):
        """
        Initialize secure chat server.

        Args:
            host (str): Server host
            port (int): Server port
            max_clients (int): Maximum clients
        """
        super().__init__(host, port, max_clients)
        self.qkd_sessions: Dict[str, QKDSession] = {}
        self.secure_channels: Dict[str, SecureChannel] = {}

    def handle_client(self, client_socket: socket.socket):
        """Handle individual client connections with QKD handshake."""
        try:
            # Receive client identity and start QKD
            identity_data = client_socket.recv(4096).decode()
            identity = json.loads(identity_data)

            client_name = identity['name']
            client_protocol = identity.get('qkd_protocol', 'BB84')
            client_key_length = identity.get('key_length', 1024)

            logger.info(f"Client {client_name} requesting QKD with {client_protocol}")

            # Perform QKD key exchange
            qkd_session = QKDSession(client_protocol, client_key_length)
            shared_key, qber, eve_detected = qkd_session.establish_key(explain=False)

            self.qkd_sessions[client_name] = qkd_session

            # Generate post-quantum key pairs for signatures
            dilithium_keypair = dilithium_keygen('Dilithium3', explain=False)
            kyber_keypair = kyber_keygen('Kyber1024', explain=False)

            # Establish secure channel
            # In a full implementation, peer public keys would be exchanged securely
            # For simulation, we'll use the same keypair (not realistic but works for demo)
            secure_channel = SecureChannel(
                qkd_secret=shared_key,
                kem_secret=kyber_keypair['public'],  # Simplified
                private_key=dilithium_keypair['private'],
                peer_public_key=dilithium_keypair['public']  # Simplified
            )

            self.secure_channels[client_name] = secure_channel

            # Send QKD results and public keys to client
            response = {
                'qkd_success': True,
                'qber': qber,
                'eve_detected': eve_detected,
                'dilithium_public': dilithium_keypair['public'].hex(),
                'kyber_public': kyber_keypair['public'].hex(),
                'session_id': client_name
            }

            client_socket.send(json.dumps(response).encode())

            logger.info(f"QKD handshake completed for {client_name}")

            # Start secure chat session
            self.start_chat_session(client_socket, client_name)

        except Exception as e:
            logger.error(f"Client handler error: {e}")
            try:
                error_msg = json.dumps({'error': str(e)}).encode()
                client_socket.send(error_msg)
            except:
                pass
        finally:
            client_socket.close()

    def start_chat_session(self, client_socket: socket.socket, client_name: str):
        """Start secure chat session for authenticated client."""
        logger.info(f"Starting secure chat for {client_name}")

        try:
            while self.running:
                # Use select to handle multiple sockets
                sockets_list = [client_socket]
                read_sockets, _, _ = select.select(sockets_list, [], [], 1.0)

                for sock in read_sockets:
                    if sock == client_socket:
                        try:
                            data = sock.recv(4096)
                            if not data:
                                logger.info(f"Client {client_name} disconnected")
                                return

                            # Decrypt and display message
                            secure_channel = self.secure_channels[client_name]
                            message_packet = json.loads(data.decode())

                            plaintext = secure_channel.decrypt_message(message_packet)
                            if plaintext:
                                timestamp = time.strftime('%H:%M:%S')
                                print(f"[{timestamp}] {client_name}: {plaintext}")

                                # Echo back for confirmation (or broadcast to others)
                                echo_packet = secure_channel.encrypt_message(f"Received: {plaintext}")
                                sock.send(json.dumps(echo_packet).encode())

                        except json.JSONDecodeError:
                            logger.warning(f"Invalid message format from {client_name}")
                        except Exception as e:
                            logger.error(f"Message handling error: {e}")
                            break

        except KeyboardInterrupt:
            logger.info("Chat session interrupted")

class SecureChatClient(ChatClient):
    """
    Enhanced chat client with QKD key exchange and secure messaging.
    """

    def __init__(self, host='localhost', port=5000):
        """
        Initialize secure chat client.
        """
        super().__init__(host, port)
        self.qkd_session: Optional[QKDSession] = None
        self.secure_channel: Optional[SecureChannel] = None
        self.dilithium_keypair: Optional[Dict[str, bytes]] = None
        self.kyber_keypair: Optional[Dict[str, bytes]] = None

    def connect(self, name: str, qkd_protocol: str = 'BB84',
                key_length: int = 1024) -> bool:
        """
        Connect to server and perform QKD handshake.

        Args:
            name (str): Client name
            qkd_protocol (str): QKD protocol to use
            key_length (int): Key length in bits

        Returns:
            bool: Connection success
        """
        if not super().connect(name):
            return False

        try:
            # Send identity and QKD parameters
            identity = {
                'name': name,
                'qkd_protocol': qkd_protocol,
                'key_length': key_length
            }
            self.socket.send(json.dumps(identity).encode())

            # Receive server response
            response_data = self.socket.recv(4096).decode()
            response = json.loads(response_data)

            if 'error' in response:
                logger.error(f"Server error: {response['error']}")
                return False

            # Extract QKD results
            qkd_success = response.get('qkd_success', False)
            qber = response.get('qber', 0.0)
            eve_detected = response.get('eve_detected', False)

            # If QKD successful, establish secure channel
            if qkd_success:
                self.qkd_session = QKDSession(qkd_protocol, key_length)
                shared_key, _, _ = self.qkd_session.establish_key(explain=False)

                # Generate local key pairs
                self.dilithium_keypair = dilithium_keygen('Dilithium3', explain=False)
                self.kyber_keypair = kyber_keygen('Kyber1024', explain=False)

                # Parse server public keys
                server_dilithium_pub = bytes.fromhex(response['dilithium_public'])
                server_kyber_pub = bytes.fromhex(response['kyber_public'])

                # Initialize secure channel
                self.secure_channel = SecureChannel(
                    qkd_secret=shared_key,
                    kem_secret=server_kyber_pub,
                    private_key=self.dilithium_keypair['private'],
                    peer_public_key=server_dilithium_pub
                )

                self.connected = True
                logger.info(".2f")
                return True
            else:
                logger.error("QKD handshake failed")
                return False

        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False

    def send_message(self, message: str):
        """
        Send encrypted message to server.

        Args:
            message (str): Message to send
        """
        if not self.secure_channel:
            logger.error("No secure channel established")
            return

        try:
            encrypted_packet = self.secure_channel.encrypt_message(message)
            data = json.dumps(encrypted_packet).encode()
            self.socket.send(data)
            logger.debug(f"Sent encrypted message: {len(data)} bytes")

        except Exception as e:
            logger.error(f"Send error: {e}")

def start_secure_chat_server(host='localhost', port=5000):
    """
    Start the secure chat server.

    Args:
        host (str): Server host
        port (int): Server port
    """
    server = SecureChatServer(host, port)
    print(f"Starting secure chat server on {host}:{port}")
    print("Press Ctrl+C to stop")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()

def start_secure_chat_client(name: str, host='localhost', port=5000):
    """
    Start the secure chat client.

    Args:
        name (str): Client name
        host (str): Server host
        port (int): Server port
    """
    client = SecureChatClient(host, port)

    if client.connect(name):
        print(f"Connected to {host}:{port} as {name}")
        print("Type your messages (Ctrl+C to quit):")

        try:
            while client.connected:
                message = input(f"{name}> ")
                if message.strip():
                    client.send_message(message)
        except KeyboardInterrupt:
            print("\nDisconnecting...")
            client.disconnect()
    else:
        print("Failed to connect")
        sys.exit(1)

# CLI integration
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Secure Chat Application')
    parser.add_argument('mode', choices=['server', 'client'], help='Run as server or client')
    parser.add_argument('--name', help='Client name (required for client mode)')
    parser.add_argument('--host', default='localhost', help='Host to connect/bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to use')

    args = parser.parse_args()

    if args.mode == 'server':
        start_secure_chat_server(args.host, args.port)
    elif args.mode == 'client':
        if not args.name:
            print("Client mode requires --name")
            sys.exit(1)
        start_secure_chat_client(args.name, args.host, args.port)
