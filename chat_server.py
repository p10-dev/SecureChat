import socket
import threading
import json
import time
import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ChatServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(3)
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificate = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.clients = {}
        self.client_certificates = {}
        self.client_challenges = {}
        self.authenticated_clients = []

        print(f"Server started on {self.host}:{self.port}")

    @staticmethod
    def send_message(client_socket, message):
        try:
            message_str = json.dumps(message)
            message_bytes = message_str.encode('utf-8')
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')
            client_socket.sendall(length_prefix + message_bytes)
        except Exception as e:
            print(f"Error sending message: {e}")

    @staticmethod
    def receive_message(client_socket):
        try:
            length_bytes = client_socket.recv(4)
            if not length_bytes:
                return None
                
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            chunks = []
            bytes_received = 0
            while bytes_received < message_length:
                chunk = client_socket.recv(min(message_length - bytes_received, 65536))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_received += len(chunk)
                
            message_bytes = b''.join(chunks)
            return json.loads(message_bytes.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None

    def handle_client_connection(self, client_socket, client_address):
        try:
            message = self.receive_message(client_socket)
            if not message or message.get('type') != 'IDENTITY':
                print("Invalid identity message")
                client_socket.close()
                return
                
            client_id = message['id']
            self.clients[client_id] = {
                'socket': client_socket,
                'address': client_address,
                'certificate': message['certificate']
            }
            print(f"Client {client_id} connected from {client_address}")
            
            self.send_message(client_socket, {
                'type': 'SERVER_IDENTITY',
                'id': 'ChatServer',
                'certificate': self.certificate.decode('utf-8')
            })
            
            message = self.receive_message(client_socket)
            if not message or message.get('type') != 'AUTHENTICATION':
                print("Invalid authentication message")
                client_socket.close()
                return
                
            try:
                client_pub_key = serialization.load_pem_public_key(
                    self.clients[client_id]['certificate'].encode('utf-8'),
                    backend=default_backend()
                )
                signature = base64.b64decode(message['signature'])
                client_pub_key.verify(
                    signature,
                    message['challenge'].encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                self.authenticated_clients.append(client_id)
                self.send_message(client_socket, {'type': 'AUTH_SUCCESS'})
            except Exception as e:
                print(f"Authentication failed: {e}")
                self.send_message(client_socket, {
                    'type': 'AUTH_FAILURE',
                    'reason': str(e)
                })
                client_socket.close()
                return
                
            print(f"Waiting for clients ({len(self.authenticated_clients)}/3)")
            while len(self.authenticated_clients) < 3:
                time.sleep(0.5)
                
            if client_id == self.authenticated_clients[0]:
                certificates = {cid: self.clients[cid]['certificate'] 
                              for cid in self.authenticated_clients}
                for cid in self.authenticated_clients:
                    self.send_message(self.clients[cid]['socket'], {
                        'type': 'CERTIFICATES',
                        'certificates': certificates
                    })
            
            while True:
                message = self.receive_message(client_socket)
                if not message:
                    break
                    
                if message['type'] == 'KEY_AGREEMENT':
                    recipient = message['to']
                    if recipient in self.clients:
                        self.send_message(self.clients[recipient]['socket'], message)
                
                elif message['type'] == 'SECURE_MESSAGE':
                    for cid in self.authenticated_clients:
                        if cid != message['from']:
                            self.send_message(self.clients[cid]['socket'], message)
                            
        except Exception as e:
            print(f"Client {client_id} error: {e}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            if client_id in self.authenticated_clients:
                self.authenticated_clients.remove(client_id)
            client_socket.close()

    def start(self):
        try:
            print("Server waiting for connections...")
            while True:
                client_socket, client_address = self.server.accept()
                threading.Thread(
                    target=self.handle_client_connection,
                    args=(client_socket, client_address),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            for client in self.clients.values():
                client['socket'].close()
            self.server.close()
