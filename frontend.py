from flask import Flask, render_template, request
import requests

app = Flask(__name__)

API_URL = "http://127.0.0.1:5000/api/incidents"

@app.route("/")
def index():
    return render_template("simple_form.html")

@app.route("/submit", methods=["POST"])
def submit():
    title = request.form.get("title")
    description = request.form.get("description")
    severity = request.form.get("severity")
    token = request.form.get("token")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    data = {
        "title": title,
        "description": description,
        "severity": severity
    }
    
    try:
        res = requests.post(API_URL, headers=headers, json=data)
        # Corrected ternary operator with parentheses
        msg = res.json().get("message") if res.status_code == 201 else res.json().get("Error")
    except Exception as e:
        msg = f"Error connecting to backend: {e}"
    
    return render_template("simple_form.html", message=msg)

if __name__ == "__main__":
    app.run(port=5001, debug=True)
