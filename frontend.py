from flask import Flask, render_template, request, redirect, session, url_for
import requests, json

app = Flask(__name__)
app.secret_key = "supersecretkey"

BACKEND_URL = "http://127.0.0.1:5000"

@app.route("/")
def login_page():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    try:
        res = requests.post(f"{BACKEND_URL}/api/login", json={"username": username, "password": password})
        res.raise_for_status()
        data = res.json()
    except requests.exceptions.RequestException as e:
        return render_template("index.html", error=f"Backend connection error: {e}")
    except json.JSONDecodeError:
        return render_template("index.html", error="Invalid response from backend")
    
    session["token"] = data.get("access_token")
    session["role"] = data.get("role")

    if data.get("role") == "admin":
        return redirect("/admin")
    else:
        return redirect("/submit")

@app.route("/submit")
def submit_page():
    if "token" not in session:
        return redirect("/")
    return render_template("submit.html")

@app.route("/submit", methods=["POST"])
def submit_incident():
    token = session.get("token")
    if not token:
        return redirect("/")
    
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "title": request.form.get("title"),
        "description": request.form.get("description"),
        "severity": request.form.get("severity")
    }
    try:
        res = requests.post(f"{BACKEND_URL}/api/incidents", json=data, headers=headers)
        res.raise_for_status()
        msg = res.json().get("message", "Incident submitted")
    except requests.exceptions.RequestException as e:
        msg = f"Backend error: {e}"
    except json.JSONDecodeError:
        msg = "Invalid response from backend"

    return render_template("submit.html", message=msg)

@app.route("/admin")
def admin_page():
    token = session.get("token")
    if not token:
        return redirect("/")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        res = requests.get(f"{BACKEND_URL}/api/incidents", headers=headers)
        res.raise_for_status()
        incidents = res.json()
    except requests.exceptions.RequestException as e:
        incidents = []
    except json.JSONDecodeError:
        incidents = []
    return render_template("admin.html", incidents=incidents)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(port=5001, debug=True)
