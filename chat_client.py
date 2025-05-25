
### 2. chat_client.py
```python
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

class ChatClient:
    def __init__(self, identity, host='127.0.0.1', port=9999):
        self.identity = identity
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
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
        
        self.server_certificate = None
        self.client_certificates = {}
        self.random_nonce = os.urandom(16).hex()
        self.session_key = None
        self.received_nonces = {}
        self.session_key_established = threading.Event()

        print(f"Client {identity} initialized with nonce: {self.random_nonce[:8]}...")

    def send_message(self, message):
        try:
            message_str = json.dumps(message)
            message_bytes = message_str.encode('utf-8')
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')
            self.client.sendall(length_prefix + message_bytes)
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_message(self):
        try:
            length_bytes = self.client.recv(4)
            if not length_bytes:
                return None
                
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            chunks = []
            bytes_received = 0
            while bytes_received < message_length:
                chunk = self.client.recv(min(message_length - bytes_received, 65536))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_received += len(chunk)
                
            message_bytes = b''.join(chunks)
            return json.loads(message_bytes.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
            
    def connect_and_authenticate(self):
        try:
            self.client.connect((self.host, self.port))
            
            self.send_message({
                'type': 'IDENTITY',
                'id': self.identity,
                'certificate': self.certificate.decode('utf-8')
            })
            print(f"Connected to server as {self.identity}")

            message = self.receive_message()
            if not message or message.get('type') != 'SERVER_IDENTITY':
                print("Invalid server identity")
                return False
            self.server_certificate = message['certificate']
            print(f"Server certificate received: {self.server_certificate[:16]}...")
            
            signature = self.private_key.sign(
                self.random_nonce.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.send_message({
                'type': 'AUTHENTICATION',
                'challenge': self.random_nonce,
                'signature': base64.b64encode(signature).decode('utf-8')
            })
            print(f"Authentication challenge sent: {self.random_nonce[:8]}...")
            
            message = self.receive_message()
            if not message or message.get('type') != 'AUTH_SUCCESS':
                print("Authentication failed")
                return False
            print("Authentication successful")
                
            message = self.receive_message()
            if not message or message.get('type') != 'CERTIFICATES':
                print("Failed to get certificates")
                return False
            self.client_certificates = message['certificates']
            
            self.received_nonces[self.identity] = self.random_nonce
            
            for client_id, cert in self.client_certificates.items():
                if client_id != self.identity:
                    try:
                        pub_key = serialization.load_pem_public_key(
                            cert.encode('utf-8'),
                            backend=default_backend()
                        )
                        plaintext = f"{self.identity}:{self.random_nonce}".encode('utf-8')
                        encrypted = pub_key.encrypt(
                            plaintext,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        hash_obj = hashlib.sha256(plaintext)
                        signature = self.private_key.sign(
                            hash_obj.digest(),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        self.send_message({
                            'type': 'KEY_AGREEMENT',
                            'from': self.identity,
                            'to': client_id,
                            'encrypted_data': base64.b64encode(encrypted).decode('utf-8'),
                            'signature': base64.b64encode(signature).decode('utf-8')
                        })
                        print(f"Key agreement sent to {client_id}")
                    except Exception as e:
                        print(f"Error sending to {client_id}: {e}")
            
            return True
            
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def derive_session_key(self):
        if len(self.received_nonces) != len(self.client_certificates):
            print(f"Need nonces from {len(self.client_certificates)} clients, have {len(self.received_nonces)}")
            return False
            
        sorted_clients = sorted(self.client_certificates.keys())
        combined = ''.join([self.received_nonces[c] for c in sorted_clients])
        self.session_key = hashlib.sha256(combined.encode()).digest()
        print(f"Session key established: {self.session_key.hex()[:16]}...")
        return True
        
    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return {
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
        
    def decrypt_message(self, encrypted):
        iv = base64.b64decode(encrypted['iv'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        tag = base64.b64decode(encrypted['tag'])
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        
    def receive_thread(self):
        while True:
            try:
                message = self.receive_message()
                if not message:
                    print("Disconnected from server")
                    break
                    
                if message['type'] == 'KEY_AGREEMENT' and message['to'] == self.identity:
                    try:
                        sender_pub_key = serialization.load_pem_public_key(
                            self.client_certificates[message['from']].encode('utf-8'),
                            backend=default_backend()
                        )
                        encrypted = base64.b64decode(message['encrypted_data'])
                        decrypted = self.private_key.decrypt(
                            encrypted,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        ).decode()
                        hash_obj = hashlib.sha256(decrypted.encode())
                        sender_pub_key.verify(
                            base64.b64decode(message['signature']),
                            hash_obj.digest(),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        sender_id, nonce = decrypted.split(':')
                        
                        if sender_id not in self.received_nonces:
                            self.received_nonces[sender_id] = nonce
                            print(f"Got nonce from {sender_id}")
                            
                            if len(self.received_nonces) == len(self.client_certificates):
                                if self.derive_session_key():
                                    self.session_key_established.set()
                    except Exception as e:
                        print(f"Error processing key agreement: {e}")
                        
                elif message['type'] == 'SECURE_MESSAGE' and self.session_key:
                    decrypted = self.decrypt_message(message['encrypted_data'])
                    print(f"\n[{message['from']}] {decrypted}")
                    print(f"{self.identity}> ", end='', flush=True)
                    
            except Exception as e:
                print(f"Receive error: {e}")
                time.sleep(1)
                
    def start(self):
        if not self.connect_and_authenticate():
            return
            
        threading.Thread(target=self.receive_thread, daemon=True).start()
        
        try:
            while True:
                if not self.session_key_established.wait(timeout=30):
                    missing = set(self.client_certificates.keys()) - set(self.received_nonces.keys())
                    print(f"\nWaiting for nonces from: {', '.join(missing)}")
                    continue
                    
                message = input(f"{self.identity}> ").strip()
                if message.lower() in ('exit', 'quit'):
                    break
                    
                if self.session_key:
                    self.send_message({
                        'type': 'SECURE_MESSAGE',
                        'from': self.identity,
                        'encrypted_data': self.encrypt_message(message)
                    })
                else:
                    print("Session key not ready")
                    
        except KeyboardInterrupt:
            print("\nDisconnecting...")
        finally:
            self.client.close()
