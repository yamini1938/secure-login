"""Automated tests for the secure login system. Run: python test_app.py"""
import os
import re
import sqlite3
import tempfile

os.environ["DATABASE"] = os.path.join(tempfile.mkdtemp(), "test.db")
import app as appmod  # noqa: E402

client = appmod.app.test_client()
PASS = "Str0ng!Pass1"
results = []


def check(name, cond):
    results.append(cond)
    print(("PASS" if cond else "FAIL"), "-", name)


def token(path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


def register(u, e, p, c=None):
    return client.post("/register", data={
        "_csrf": token("/register"), "username": u, "email": e,
        "password": p, "confirm": c or p})


def login(u, p):
    return client.post("/login", data={"_csrf": token("/login"), "username": u, "password": p})


# 1. Registration works and password is hashed with bcrypt
r = register("alice", "alice@example.com", PASS)
check("valid registration redirects to login", r.status_code == 302)
row = sqlite3.connect(appmod.DATABASE).execute(
    "SELECT password_hash FROM users WHERE username='alice'").fetchone()
check("password stored as bcrypt hash (not plain text)",
      row[0].startswith(b"$2b$") and PASS.encode() not in row[0])

# 2. Validation
check("weak password rejected", register("bob", "bob@example.com", "password").status_code == 400)
check("bad email rejected", register("bob", "not-an-email", PASS).status_code == 400)
check("username with SQL chars rejected", register("bob'; DROP TABLE users;--", "b@e.com", PASS).status_code == 400)
check("password mismatch rejected", register("bob", "bob@example.com", PASS, "Different1!").status_code == 400)
check("duplicate username rejected", register("alice", "other@example.com", PASS).status_code == 409)

# 3. SQL injection against login
r = login("' OR '1'='1' --", "anything")
check("SQLi login bypass fails", r.status_code == 401)
r = login("alice", "' OR '1'='1")
check("SQLi in password fails", r.status_code == 401)
count = sqlite3.connect(appmod.DATABASE).execute("SELECT COUNT(*) FROM users").fetchone()[0]
check("users table intact after injection attempts", count == 1)

# 4. Session handling
check("dashboard blocked when logged out", client.get("/dashboard").status_code == 302)
r = login("alice", PASS)
check("correct login succeeds", r.status_code == 302)
check("dashboard accessible when logged in", client.get("/dashboard").status_code == 200)
cookie = r.headers.get("Set-Cookie", "")
check("session cookie is HttpOnly", "HttpOnly" in cookie)
client.post("/logout", data={"_csrf": token("/dashboard")})
check("dashboard blocked after logout", client.get("/dashboard").status_code == 302)

# 5. CSRF
check("POST without CSRF token rejected",
      client.post("/login", data={"username": "alice", "password": PASS}).status_code == 400)

# 6. Security headers
h = client.get("/login").headers
check("security headers present",
      h.get("X-Frame-Options") == "DENY" and "Content-Security-Policy" in h)

# 7. Brute-force lockout
for _ in range(5):
    login("alice", "wrong")
check("account locked after repeated failures", login("alice", PASS).status_code == 429)

print(f"\n{sum(results)}/{len(results)} tests passed")
raise SystemExit(0 if all(results) else 1)
