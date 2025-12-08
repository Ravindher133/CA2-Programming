from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///threat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

import bcrypt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())  

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

@app.route("/api/register", methods=["POST"])
def home():
    return {"message": "Threat API Running"}

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)