from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps  

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "mysecret"

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    new_user = User(
        username=username,
        password_hash=hash_password(password)
    )

    db.session.add(new_user)
    db.session.commit()

    return {"message": "User registered successfully"}

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    username = data["username"]
    password = data["password"]

    user = User.query.filter_by(username=username).first()
    
    if not user or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {"username": username, "exp": datetime.utcnow() + timedelta(hours=5)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    return jsonify({"token": token})

def token_required(f):
    @wraps(f)        
    def decorated(*args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data["username"]).first()
        except:
            return jsonify({"error": "Token is invalid or expired!"}), 401

        return f(current_user, *args, **kwargs)
    return decorated

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route("/api/incidents", methods=["POST"])
@token_required
def create_incident(current_user):
    data = request.get_json(silent=True)
    
    if not data:
        return jsonify({"error": "Missing Json data"}), 400
    
    required_fields = ["title", "description", "severity"]
    missing =[f for f in required_fields if f not in data]
    
    if missing:
        return jsonify({"error": f"Missing fields: {','.join(missing)}"}), 400
    
    new_incident = Incident(
        title=data["title"],
        description=data.get("description"),
        severity=data.get("severity", "Low"),
        status="Open"
    )

    db.session.add(new_incident)
    db.session.commit()

    return jsonify({"message": "Incident created successfully!"}), 201

@app.route("/api/incidents", methods=["GET"])
@token_required
def list_incidents(current_user):
    incidents = Incident.query.all()

    output = []
    for inc in incidents:
        output.append({
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "created_at": inc.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({"incidents": output})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
