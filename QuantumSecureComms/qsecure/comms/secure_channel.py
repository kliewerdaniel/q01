"""
Secure Communication Channel Implementation

This module provides secure channels for quantum-resilient messaging,
integrating QKD, PQC signatures, and hybrid encryption.
"""

import json
import socket
import threading
import time
from typing import Callable, Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

from ..hybrid.hybrid import HybridCrypto
from ..pqc.dilithium import dilithium_sign, dilithium_verify
from ..utils.logger import get_logger

logger = get_logger(__name__)

class SecureChannel:
    """
    Secure bidirectional communication channel with quantum-resilient encryption.
    
    Features:
    - Hybrid encryption (QKD + PQC)
    - Digital signature authentication (Dilithium)
    - Forward secrecy
    """
    
    def __init__(self, qkd_secret: bytes, kem_secret: bytes, private_key: bytes, peer_public_key: bytes):
        """
        Initialize secure channel with shared secrets and keys.
        
        Args:
            qkd_secret (bytes): Shared secret from QKD
            kem_secret (bytes): Shared secret from PQC KEM
            private_key (bytes): Dilithium private key for signing
            peer_public_key (bytes): Dilithium public key for verification
        """
        self.hybrid = HybridCrypto(qkd_secret, kem_secret)
        self.private_key = private_key
        self.peer_public_key = peer_public_key
        self.sequence_number = 0
        
        logger.info("Secure channel initialized")
    
    def encrypt_message(self, message: str) -> Dict[str, Any]:
        """
        Encrypt and sign a message for secure transmission.

        Args:
            message (str): Plaintext message

        Returns:
            Dict[str, Any]: Encrypted packet with ciphertext, signature, nonce, etc.
        """
        # Convert message to bytes
        message_bytes = message.encode('utf-8')

        # Encrypt with AES-GCM
        ciphertext, nonce, tag, salt = self.hybrid.encrypt_data(message_bytes)

        # Sign the ciphertext with Dilithium
        signature = dilithium_sign(ciphertext, self.private_key)

        # Create authenticated packet
        packet = {
            'seq': self.sequence_number,
            'ciphertext': ciphertext.hex(),
            'nonce': nonce.hex(),
            'tag': tag.hex(),
            'salt': salt.hex(),
            'signature': signature.hex(),
            'timestamp': int(time.time())
        }

        self.sequence_number += 1

        logger.debug(f"Message encrypted: seq={packet['seq']}")
        return packet
    
    def decrypt_message(self, packet: Dict[str, Any]) -> Optional[str]:
        """
        Decrypt and verify a received message.

        Args:
            packet (Dict[str, Any]): Received encrypted packet

        Returns:
            Optional[str]: Decrypted message or None if verification failed
        """
        try:
            # Extract packet components
            seq = packet['seq']
            ciphertext = bytes.fromhex(packet['ciphertext'])
            nonce = bytes.fromhex(packet['nonce'])
            tag = bytes.fromhex(packet['tag'])
            salt = bytes.fromhex(packet['salt'])
            signature = bytes.fromhex(packet['signature'])

            # Verify signature first
            if not dilithium_verify(ciphertext, signature, self.peer_public_key):
                logger.warning(f"Signature verification failed for seq={seq}")
                return None

            # Decrypt the message
            plaintext_bytes = self.hybrid.decrypt_data(
                ciphertext, nonce, tag, salt
            )

            plaintext = plaintext_bytes.decode('utf-8')

            logger.debug(f"Message decrypted: seq={seq}")
            return plaintext

        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            return None

    def authenticate_peer(self, challenge: bytes) -> bytes:
        """
        Authenticate peer by signing a challenge.
        
        Args:
            challenge (bytes): Random challenge
            
        Returns:
            bytes: Signature of challenge
        """
        return dilithium_sign(challenge, self.private_key)

class ChatServer:
    """
    TCP server for secure chat sessions.
    """
    
    def __init__(self, host='localhost', port=5000, max_clients=2):
        """
        Initialize chat server.
        
        Args:
            host (str): Server host
            port (int): Server port
            max_clients (int): Maximum clients
        """
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.server_socket = None
        self.clients = {}  # client_socket -> {'name': str, 'channel': SecureChannel}
        self.running = False
        
        logger.info(f"Chat server initialized on {host}:{port}")
    
    def start(self):
        """Start the chat server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_clients)
        
        self.running = True
        logger.info("Chat server started")
        
        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                logger.info(f"New connection from {addr}")
                
                # Start client handler thread
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.start()
                
        except KeyboardInterrupt:
            self.stop()
    
    def handle_client(self, client_socket: socket.socket):
        """Handle individual client connections."""
        try:
            # Receive client name
            name_data = client_socket.recv(1024).decode()
            name = json.loads(name_data)['name']
            
            logger.info(f"Client {name} connected")
            
            # TODO: Implement secure handshake
            # For now, assume pre-shared keys
            
        except Exception as e:
            logger.error(f"Client handler error: {e}")
        finally:
            client_socket.close()
    
    def stop(self):
        """Stop the chat server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Chat server stopped")
    
    def broadcast(self, message: str, sender: str):
        """Broadcast message to all connected clients."""
        # TODO: Use secure channel for encrypted broadcast
        logger.debug(f"Broadcast: {sender}: {message}")

class ChatClient:
    """
    TCP client for secure chat sessions.
    """
    
    def __init__(self, host='localhost', port=5000):
        """
        Initialize chat client.
        
        Args:
            host (str): Server host
            port (int): Server port
        """
        self.host = host
        self.port = port
        self.socket = None
        self.name = ""
        self.connected = False
        
        logger.info("Chat client initialized")
    
    def connect(self, name: str) -> bool:
        """
        Connect to chat server.
        
        Args:
            name (str): Client name
            
        Returns:
            bool: Connection success
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.name = name
            self.connected = True
            
            # Send name to server
            name_data = json.dumps({'name': name}).encode()
            self.socket.send(name_data)
            
            logger.info(f"Connected to server as {name}")
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def send_message(self, message: str):
        """
        Send message to server.
        
        TODO: Encrypt message with secure channel
        """
        try:
            # For now, send plaintext (placeholder)
            data = json.dumps({'message': message}).encode()
            self.socket.send(data)
            logger.debug(f"Sent: {message}")
            
        except Exception as e:
            logger.error(f"Send failed: {e}")
    
    def disconnect(self):
        """Disconnect from server."""
        if self.socket:
            self.socket.close()
        self.connected = False
        logger.info("Disconnected from server")
