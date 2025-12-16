import os
import re
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import firebase_admin
from firebase_admin import credentials, firestore

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from email_validator import validate_email, EmailNotValidError


# -----------------------
# App + Secrets
# -----------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-this")


# -----------------------
# Firebase / Firestore
# -----------------------
cred = credentials.Certificate("firebase-key.json")
firebase_admin.initialize_app(cred)
fs = firestore.client()

serializer = URLSafeTimedSerializer(app.secret_key)


# -----------------------
# Login manager
# -----------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# -----------------------
# Helpers
# -----------------------
class SimpleUser(UserMixin):
    def __init__(self, email: str):
        self.id = email
        self.email = email


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def update_user_fields(email: str, fields: dict):
    fs.collection("users").document(email).set(fields, merge=True)


def block_common_typos(domain: str):
    typos = {
        "gma.com": "gmail.com",
        "gmial.com": "gmail.com",
        "gamil.com": "gmail.com",
        "gnail.com": "gmail.com",
        "hotnail.com": "hotmail.com",
        "outllok.com": "outlook.com",
    }
    return typos.get(domain.lower())


def is_valid_real_email(email: str) -> tuple[bool, str]:
    """
    Validates email format + DNS/MX deliverability checks + blocks common typo domains.
    Returns (True, normalized_email) or (False, error_message).
    """
    try:
        v = validate_email(email, check_deliverability=True)
        normalized = v.email
        domain = normalized.split("@", 1)[1].lower()

        suggestion = block_common_typos(domain)
        if suggestion:
            local_part = normalized.split("@", 1)[0]
            return False, f"Did you mean {local_part}@{suggestion} ?"

        return True, normalized
    except EmailNotValidError as e:
        return False, str(e)


def is_strong_password(password: str) -> tuple[bool, str]:
    """
    Must contain:
    - min 8 chars
    - 1 lowercase, 1 uppercase, 1 number, 1 special
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def get_user_by_email(email: str):
    doc = fs.collection("users").document(email).get()
    return doc.to_dict() if doc.exists else None


def create_user(email: str, password_hash: str):
    fs.collection("users").document(email).set({
        "email": email,
        "password_hash": password_hash,
        "verified": False,

        # Rate limit fields
        "failed_attempts": 0,
        "last_failed_login": None,

        # Last login timestamp
        "last_login": None
    })


def mark_user_verified(email: str):
    update_user_fields(email, {"verified": True})


def send_verification_email(to_email: str):
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    from_email = os.environ.get("FROM_EMAIL", smtp_user)
    base_url = os.environ.get("BASE_URL", "http://127.0.0.1:5001")

    if not smtp_host or not smtp_user or not smtp_pass:
        raise RuntimeError("Email sending is not configured. (Missing SMTP env vars.)")

    token = serializer.dumps(to_email, salt="email-verify")
    link = f"{base_url}/verify-email?token={token}"

    msg = EmailMessage()
    msg["Subject"] = "Verify your email"
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(
        "Hi!\n\n"
        "Please verify your email by clicking this link:\n"
        f"{link}\n\n"
        "If you didn’t create this account, ignore this email.\n"
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

    except smtplib.SMTPRecipientsRefused:
        raise RuntimeError("That email address could not receive mail. Please check for typos (e.g. gmail.com).")
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError("Email sender authentication failed. Use an App Password and re-check SMTP_USER/SMTP_PASS.")
    except smtplib.SMTPException:
        raise RuntimeError("Verification email could not be sent right now. Please try again.")


def lockout_remaining(user_data: dict) -> timedelta | None:
    """
    After 3 failed attempts, block for 10 minutes from last_failed_login.
    Returns remaining timedelta if locked, else None.
    """
    attempts = int(user_data.get("failed_attempts", 0) or 0)
    last_failed = user_data.get("last_failed_login")

    if attempts < 3 or not last_failed:
        return None

    # Firestore timestamps often come as datetime; ensure tz-aware
    if isinstance(last_failed, datetime) and last_failed.tzinfo is None:
        last_failed = last_failed.replace(tzinfo=timezone.utc)

    if not isinstance(last_failed, datetime):
        return None

    window = timedelta(minutes=10)
    elapsed = utc_now() - last_failed
    if elapsed < window:
        return window - elapsed

    return None


@login_manager.user_loader
def load_user(user_id):
    data = get_user_by_email(user_id)
    if not data:
        return None
    return SimpleUser(data["email"])


# -----------------------
# Routes
# -----------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("You’re already logged in. Logout to create another account.", "info")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        ok, normalized_or_msg = is_valid_real_email(email)
        if not ok:
            flash(f"Invalid email: {normalized_or_msg}", "error")
            return redirect(url_for("register"))
        email = normalized_or_msg

        if not password or not confirm:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        ok, msg = is_strong_password(password)
        if not ok:
            flash(msg, "error")
            return redirect(url_for("register"))

        existing = get_user_by_email(email)
        if existing:
            flash("An account with that email already exists.", "error")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)
        create_user(email, pw_hash)

        try:
            send_verification_email(email)
        except Exception as e:
            flash(f"Account created, but email could not be sent: {e}", "error")
            flash("Fix your email and use 'Resend verification email' on the login page.", "error")
            return redirect(url_for("login"))

        flash("Account created! Please verify your email before logging in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/verify-email")
def verify_email():
    token = request.args.get("token", "")
    if not token:
        return "Missing token.", 400

    try:
        email = serializer.loads(token, salt="email-verify", max_age=60 * 60)  # 1 hour
    except SignatureExpired:
        return "Verification link expired. Please request a new one.", 400
    except BadSignature:
        return "Invalid verification link.", 400

    mark_user_verified(email)
    flash("Email verified! You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    if current_user.is_authenticated:
        flash("You’re already logged in.", "info")
        return redirect(url_for("dashboard"))

    email = request.form.get("email", "").strip().lower()

    ok, normalized_or_msg = is_valid_real_email(email)
    if not ok:
        flash(f"Invalid email: {normalized_or_msg}", "error")
        return redirect(url_for("login"))
    email = normalized_or_msg

    user_data = get_user_by_email(email)
    if not user_data:
        flash("No account found for that email.", "error")
        return redirect(url_for("login"))

    if user_data.get("verified", False):
        flash("Email already verified. Please log in.", "success")
        return redirect(url_for("login"))

    try:
        send_verification_email(email)
    except Exception as e:
        flash(f"Could not send verification email: {e}", "error")
        return redirect(url_for("login"))

    flash("Verification email resent. Please check your inbox.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash("You’re already logged in. Logout to switch accounts.", "info")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        ok, normalized_or_msg = is_valid_real_email(email)
        if not ok:
            flash(f"Invalid email: {normalized_or_msg}", "error")
            return redirect(url_for("login"))
        email = normalized_or_msg

        if not password:
            flash("Please enter your password.", "error")
            return redirect(url_for("login"))

        user_data = get_user_by_email(email)

        # If user exists, enforce lockout rules
        if user_data:
            remaining = lockout_remaining(user_data)
            if remaining:
                mins = int(remaining.total_seconds() // 60)
                secs = int(remaining.total_seconds() % 60)
                flash(f"Too many failed attempts. Try again in {mins}m {secs}s.", "error")
                return redirect(url_for("login"))
            else:
                # If lock window passed but attempts >= 3, reset attempts
                attempts = int(user_data.get("failed_attempts", 0) or 0)
                last_failed = user_data.get("last_failed_login")
                if attempts >= 3 and last_failed:
                    update_user_fields(email, {"failed_attempts": 0, "last_failed_login": None})
                    user_data["failed_attempts"] = 0
                    user_data["last_failed_login"] = None

        # Validate credentials
        if (not user_data) or (not check_password_hash(user_data["password_hash"], password)):
            # Update failed attempt counters ONLY if user exists (prevents user-enumeration + avoids creating docs)
            if user_data:
                attempts = int(user_data.get("failed_attempts", 0) or 0) + 1
                now = utc_now()
                update_user_fields(email, {
                    "failed_attempts": attempts,
                    "last_failed_login": now
                })

                if attempts >= 3:
                    flash("Too many failed attempts. Your login is blocked for 10 minutes.", "error")
                else:
                    remaining_tries = 3 - attempts
                    flash(f"Invalid email or password. {remaining_tries} attempt(s) left before 10 min lock.", "error")
            else:
                flash("Invalid email or password.", "error")

            return redirect(url_for("login"))

        # Must be verified
        if not user_data.get("verified", False):
            flash("Please verify your email before logging in.", "error")
            flash("If you didn’t receive it, use the resend form below.", "error")
            return redirect(url_for("login"))

        # SUCCESS: log in, reset lockout counters, store last_login
        update_user_fields(email, {
            "failed_attempts": 0,
            "last_failed_login": None,
            "last_login": utc_now()
        })

        login_user(SimpleUser(email))
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    data = get_user_by_email(current_user.email) or {}
    last_login = data.get("last_login")

    last_login_str = None
    if isinstance(last_login, datetime):
        # Display in a simple readable format (UTC)
        if last_login.tzinfo is None:
            last_login = last_login.replace(tzinfo=timezone.utc)
        last_login_str = last_login.strftime("%Y-%m-%d %H:%M:%S UTC")

    return render_template("dashboard.html", email=current_user.email, last_login=last_login_str)


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
