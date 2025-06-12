from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import pyotp, base64, qrcode
from datetime import datetime, timedelta
from models import db, User, PasswordVault
from vault_crypto import encrypt_password, decrypt_password
import uuid

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return {"message": "Flask backend is running ✅"}

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json()
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")

    if not all([email, password, first_name, last_name]):
        return jsonify({"message": "All fields are required."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered."}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password_hash=hashed_password,
        password_last_changed=datetime.utcnow()
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.all()
    users_list = [{"id": u.id, "email": u.email} for u in users]
    return jsonify(users_list)

@app.route("/api/users/<string:email>", methods=["GET"])
def get_user_details(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name
    })

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        # Check if password is older than 4 months
        expired = False
        if user.password_last_changed:
            age = datetime.utcnow() - user.password_last_changed
            expired = age > timedelta(days=120)

        return jsonify({
            "success": True,
            "message": "Login successful!",
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password_expired": expired  # 👈 Send this flag
        })

    return jsonify({"success": False, "message": "Invalid credentials"}), 401

#update user api
@app.route("/api/users/update", methods=["PUT"])
def update_user():
    data = request.get_json()
    email = data.get("email")
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not email:
        return jsonify({"message": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Update name fields if provided
    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name

    # If password change is requested
    if new_password:
        if not current_password:
            return jsonify({"message": "Current password is required to change password"}), 400
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({"message": "Current password is incorrect"}), 401

        user.password_hash = generate_password_hash(new_password)
        user.password_last_changed = datetime.utcnow()

    db.session.commit()
    return jsonify({"message": "User updated successfully!"}), 200

@app.route("/api/mfa/generate", methods=["POST"])
def generate_mfa():
    email = request.json.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.session.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="SecureVault")
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({"qr_image": qr_b64})

@app.route("/api/mfa/verify", methods=["POST"])
def verify_code():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()
    if user and pyotp.TOTP(user.mfa_secret).verify(data["code"]):
        return jsonify({"success": True})
    return jsonify({"success": False}), 401

# ==== PASSWORD VAULT ROUTES ====

@app.route("/api/passwords", methods=["GET"])
def get_passwords():
    email = request.args.get("email")
    page = int(request.args.get("page", 1))
    per_page = 5

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"entries": [], "total_pages": 0})

    query = PasswordVault.query.filter_by(user_id=user.id)
    total = query.count()
    entries = query.paginate(page=page, per_page=per_page, error_out=False).items

    result = [
        {
            "id": entry.id,
            "site": entry.site,
            "username": entry.username,
            "password": decrypt_password(entry.password),
            "notes": entry.notes
        }
        for entry in entries
    ]

    return jsonify({"entries": result, "total_pages": (total + per_page - 1) // per_page})



@app.route("/api/passwords", methods=["POST"])
def add_password():
    data = request.get_json()
    email = data.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    new_entry = PasswordVault(
        site=data["site"],
        username=data["username"],
        password=encrypt_password(data["password"]),
        notes=data.get("notes", ""),
        user_id=user.id
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": "Password added"}), 201

@app.route("/api/passwords/<int:id>", methods=["GET"])
def get_single_password(id):
    entry = PasswordVault.query.get_or_404(id)
    return jsonify({
        "id": entry.id,
        "site": entry.site,
        "username": entry.username,
        "password": decrypt_password(entry.password),
        "notes": entry.notes
    })

@app.route("/api/passwords/<int:id>", methods=["PUT"])
def update_password(id):
    data = request.get_json()
    entry = PasswordVault.query.get_or_404(id)

    entry.site = data["site"]
    entry.username = data["username"]
    entry.password = encrypt_password(data["password"])
    entry.notes = data.get("notes", "")

    db.session.commit()
    return jsonify({"message": "Password updated"})

@app.route("/api/passwords/<int:id>", methods=["DELETE"])
def delete_password(id):
    entry = PasswordVault.query.get_or_404(id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"message": "Password deleted"})

if __name__ == "__main__":
    app.run(debug=True)
