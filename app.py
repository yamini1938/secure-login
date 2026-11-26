"""Secure Login & Registration System - PRMA Tech Internship, Week 1.

Security features:
  * Password hashing with bcrypt (salted, cost factor 12)
  * Parameterized SQL queries (prevents SQL Injection)
  * Server-side input validation
  * Session management (HttpOnly cookie, timeout, session reset on login)
  * CSRF tokens on every form
  * Login attempt limiting (basic brute-force protection)
  * Security headers
"""
import os
import re
import secrets
import sqlite3
import time
from functools import wraps

import bcrypt
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",  # set HTTPS=1 in production
    PERMANENT_SESSION_LIFETIME=1800,  # 30-minute session timeout
)

DATABASE = os.environ.get("DATABASE", os.path.join(os.path.dirname(__file__), "users.db"))

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed = {}  # (ip, username) -> (count, first_fail_time)  [in-memory, demo only]


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP)"""
        )


# ---------------------------------------------------------------- security helpers
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def password_errors(p):
    errs = []
    if len(p) < 8:
        errs.append("at least 8 characters")
    if len(p) > 72:  # bcrypt limit
        errs.append("at most 72 characters")
    if not re.search(r"[A-Z]", p):
        errs.append("an uppercase letter")
    if not re.search(r"[a-z]", p):
        errs.append("a lowercase letter")
    if not re.search(r"\d", p):
        errs.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", p):
        errs.append("a special character")
    return errs


def is_locked(key):
    rec = _failed.get(key)
    if not rec:
        return False
    count, first = rec
    if time.time() - first > LOCKOUT_SECONDS:
        _failed.pop(key, None)
        return False
    return count >= MAX_ATTEMPTS


def record_failure(key):
    count, first = _failed.get(key, (0, time.time()))
    _failed[key] = (count + 1, first)


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-20 characters: letters, numbers, underscore."
        elif not EMAIL_RE.match(email) or len(email) > 254:
            error = "Please enter a valid email address."
        elif password_errors(password):
            error = "Password needs " + ", ".join(password_errors(password)) + "."
        elif password != confirm:
            error = "Passwords do not match."

        if error:
            flash(error, "error")
            return render_template("register.html", username=username, email=email), 400

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        try:
            db = get_db()
            # Parameterized query: user input is NEVER concatenated into SQL.
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hashed),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username or email is already registered.", "error")
            return render_template("register.html", username=username, email=email), 409

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = (request.remote_addr, username.lower())

        if is_locked(key):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Always run a bcrypt check so timing doesn't reveal whether the user exists.
        stored = row[1] if row else bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12))
        ok = bcrypt.checkpw(password.encode()[:72], stored)

        if row and ok:
            _failed.pop(key, None)
            session.clear()  # prevents session fixation
            session["user_id"] = row[0]
            session["username"] = username
            session.permanent = True
            return redirect(url_for("dashboard"))

        record_failure(key)
        flash("Invalid username or password.", "error")  # generic on purpose
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=False)  # never run debug=True in production
