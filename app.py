from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
import jwt, bcrypt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///threat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "mysecret"

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User", backref="incidents")

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth = request.headers["Authorization"]
            if auth.startswith("Bearer "):
                token = auth.split(" ")[1]
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data["username"]).first()
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        return render_template("login.html", error="Invalid credentials")
    session["username"] = user.username
    session["role"] = user.role
    if user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    else:
        return redirect(url_for("user_page"))

@app.route("/user")
def user_page():
    if "username" not in session or session.get("role") != "user":
        return redirect(url_for("login_page"))
    return render_template("index.html")

@app.route("/admin")
def admin_dashboard():
    if "username" not in session or session.get("role") != "admin":
        return redirect(url_for("login_page"))
    incidents = Incident.query.all()
    return render_template("admin.html", incidents=incidents)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400
    new_user = User(
        username=username,
        password_hash=hash_password(password),
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode(
        {"username": user.username, "role": user.role, "exp": datetime.utcnow() + timedelta(hours=2)},
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )
    return jsonify({"access_token": token, "role": user.role}), 200

@app.route("/api/incidents", methods=["POST"])
@token_required
def create_incident(current_user):
    data = request.json or {}
    new_incident = Incident(
        title=data.get("title"),
        description=data.get("description"),
        severity=data.get("severity"),
        user_id=current_user.id
    )
    db.session.add(new_incident)
    db.session.commit()
    return jsonify({"message": "Incident created"}), 201

@app.route("/api/incidents", methods=["GET"])
@token_required
def list_incidents(current_user):
    incidents = Incident.query.all()
    return jsonify([{
        "id": i.id,
        "title": i.title,
        "severity": i.severity,
        "status": i.status
    } for i in incidents])

def create_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password_hash=hash_password("admin123"), role="admin")
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True)
