from cryptography.fernet import Fernet
import json
import os

# Load or generate key
KEY_FILE = "secret.key"

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    key = f.read()

cipher = Fernet(key)

def encrypt_vault(vault_data):
    json_data = json.dumps(vault_data)
    encrypted = cipher.encrypt(json_data.encode())
    return encrypted.decode()

def decrypt_vault(encrypted_data):
    decrypted = cipher.decrypt(encrypted_data.encode()).decode()
    return json.loads(decrypted)