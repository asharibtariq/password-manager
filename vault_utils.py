from cryptography.fernet import Fernet

# You should store this key securely in environment variables
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_vault(data_dict):
    import json
    plaintext = json.dumps(data_dict).encode()
    return cipher.encrypt(plaintext).decode()

def decrypt_vault(encrypted_str):
    decrypted = cipher.decrypt(encrypted_str.encode())
    return decrypted.decode()