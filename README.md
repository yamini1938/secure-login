# 🔐 Secure Login & Registration System

Week 1 project of the **PRMA Tech Internship – Cyber Security & Ethical Hacking**.
A Flask web app with registration, login, and a protected dashboard, built with security best practices.

## Features

| Security Control | Implementation |
|---|---|
| Password hashing | `bcrypt` with per-user salt, cost factor 12 |
| SQL Injection prevention | Parameterized queries (`?` placeholders), never string concatenation |
| Input validation | Regex whitelist for username/email, password complexity rules (server-side) |
| Session management | HttpOnly + SameSite cookies, 30-minute timeout, `session.clear()` on login/logout (prevents session fixation) |
| CSRF protection | Per-session token on every POST form |
| Brute-force protection | Account/IP lockout after 5 failed logins (5 min) |
| User enumeration protection | Generic error messages + constant-time bcrypt check |
| XSS protection | Jinja2 auto-escaping + Content-Security-Policy header |
| Security headers | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control: no-store` |

## Project Structure

```
secure-login/
├── app.py              # Flask app (routes, validation, security logic)
├── test_app.py         # Automated security tests
├── requirements.txt
├── static/style.css
└── templates/          # base, register, login, dashboard
```

## Setup & Run

```bash
git clone https://github.com/<your-username>/secure-login.git
cd secure-login
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

For production, set `SECRET_KEY` and `HTTPS=1` environment variables and serve behind HTTPS.

## Run the tests

```bash
python test_app.py
```

## Core Concepts Applied (CIA Triad)

- **Confidentiality** – passwords are hashed (never stored in plain text); sessions are protected cookies.
- **Integrity** – parameterized queries and CSRF tokens stop attackers from tampering with data/requests.
- **Availability** – login lockout limits brute-force abuse; session timeout limits exposure.

## Screenshots

_Add screenshots of the register page, login page, dashboard, and the failed SQL injection attempt here._

## Limitations / Future Work

- Lockout counter is in-memory (use Redis or a DB in production).
- Add email verification, password reset, and 2FA.

## Disclaimer

Educational project built for an authorized internship lab.
