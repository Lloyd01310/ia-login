from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)
cred = credentials.Certificate("firebase-key.json")
firebase_admin.initialize_app(cred)
fs = firestore.client()
app.config["SECRET_KEY"] = "change-this-to-a-random-string"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

from flask_login import UserMixin

class SimpleUser(UserMixin):
    def __init__(self, email: str):
        self.id = email          # Flask-Login stores this in the session
        self.email = email       # for displaying on dashboard


def get_user_by_email(email: str):
    doc = fs.collection("users").document(email).get()
    return doc.to_dict() if doc.exists else None


def create_user(email: str, password_hash: str):
    fs.collection("users").document(email).set({
        "email": email,
        "password_hash": password_hash
    })

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    data = get_user_by_email(user_id)  # user_id is the email
    if not data:
        return None
    return SimpleUser(data["email"])

@app.route("/")
def home():
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # Server-side validation
        if not email or not password or not confirm:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))
        if "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        existing = get_user_by_email(email)
        if existing:
            flash("An account with that email already exists.", "error")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)
        create_user(email, pw_hash)

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))


    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter email and password.", "error")
            return redirect(url_for("login"))

        user_data = get_user_by_email(email)
        if (not user_data) or (not check_password_hash(user_data["password_hash"], password)):
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        login_user(SimpleUser(user_data["email"]))  # session persistence ✅
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))


    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", email=current_user.email)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

@app.route("/firebase-test")
def firebase_test():
    fs.collection("test").document("hello").set({"msg": "Firebase connected"})
    return "Firebase is working!"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
