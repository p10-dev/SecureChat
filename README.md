# SecureChat: Secure Key Establishment Protocol

A secure chat system designed for three participants using mutual authentication, confidentiality, and integrity mechanisms (RSA, AES-GCM, SHA-256).

## 📜 Overview

SecureChat implements a protocol that allows three clients to:
- Authenticate using certificates
- Derive a shared session key `K_ABC = H(Na || Nb || Nc)`
- Exchange encrypted group messages

## 🛡️ Security Features

| Feature         | Algorithm          |
|----------------|--------------------|
| Authentication | RSA Digital Signature |
| Confidentiality| AES-GCM (Session Key) |
| Integrity      | SHA-256            |
| Key Exchange   | RSA + Nonce Hashing |

## 🚀 How to Run

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run the server
python run.py server

# Run each client (in separate terminals)
python run.py client --id Alice
python run.py client --id Bob
python run.py client --id Charlie
```

## 📂 Files

- `chat_server.py` – Server logic
- `chat_client.py` – Client logic
- `run.py` – Entry script
- `config.py` – Shared constants (optional)
- `requirements.txt` – Python dependencies

## 👨‍🏫 Authors

- Nnamdi Philip Okonkwo (24013366)
- Abhishek Meeneshwar Ayare (24171522)
- Neeraj Kumar Singh (24026417)
- Sarthak Ajay Mishra (24199842)

Supervisor: Prof. Thomas Newe
