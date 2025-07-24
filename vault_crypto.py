from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

load_dotenv()  # Loads variables from .env

fernet_key = os.getenv("FERNET_KEY")
if not fernet_key:
    raise ValueError("FERNET_KEY not found in .env!")

fernet = Fernet(fernet_key.encode())

def encrypt_password(password: str) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()
