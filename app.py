from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from models import db, User
from vault_utils import encrypt_vault, decrypt_vault
import pyotp, base64, qrcode
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

# Configure database (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create DB tables
with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return {"message": "Flask backend is running ✅"}



# === Registration ===
@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return jsonify({}), 200  # Preflight request
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"})

# === Users Get ===

@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.all()
    users_list = [{"id": u.id, "email": u.email} for u in users]
    return jsonify(users_list)

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        return jsonify({"success": True, "message": "Login successful!"})
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

# === Generate MFA QR Code ===
@app.route("/api/mfa/generate", methods=["POST"])
def generate_mfa():
    email = request.json.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db.session.add(user)

    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.session.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="SecureVault")
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({"qr_image": qr_b64})

# === Verify MFA Code ===
@app.route("/api/mfa/verify", methods=["POST"])
def verify_code():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()
    if user and pyotp.TOTP(user.mfa_secret).verify(data["code"]):
        return jsonify({"success": True})
    return jsonify({"success": False}), 401

# === Store Encrypted Vault Data ===
@app.route("/api/vault/save", methods=["POST"])
def save_vault():
    data = request.get_json()
    email = data["email"]
    vault = data["vault"]  # dictionary of entries

    user = User.query.filter_by(email=email).first()
    if user:
        user.encrypted_vault = encrypt_vault(vault)
        db.session.commit()
        return jsonify({"message": "Vault saved."})
    return jsonify({"message": "User not found."}), 404

# === Fetch & Decrypt Vault ===
@app.route("/api/vault/get", methods=["POST"])
def get_vault():
    email = request.json.get("email")
    user = User.query.filter_by(email=email).first()
    if user and user.encrypted_vault:
        decrypted = decrypt_vault(user.encrypted_vault)
        return jsonify({"vault": decrypted})
    return jsonify({"vault": None})

if __name__ == "__main__":
    app.run(debug=True)