from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from crypto_utils import encrypt, decrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# ---------------- DB INIT ----------------
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- SECURITY ----------------
@app.before_request
def check_security():
    allowed = ["login", "register", "static"]

    if request.endpoint in allowed or request.endpoint is None:
        return

    if not session.get("user") and not session.get("admin"):
        return jsonify({"error": "Not logged in"}), 403

# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect("/login")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = encrypt(request.form["password"])

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("INSERT INTO users VALUES (NULL, ?, ?)", (username, password))
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ADMIN
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=?", (username,))
        data = cur.fetchone()
        conn.close()

        if data and decrypt(data[0]) == password:
            session["user"] = username
            return redirect("/dashboard")

        return "Invalid credentials ❌"

    return render_template("login.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))

# ---------------- ADMIN ----------------
@app.route("/admin")
def admin():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template("admin.html", users=users)

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
