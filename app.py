import hashlib
import html
import json
import os
import re
import time
import threading
import secrets
from collections import OrderedDict
from functools import wraps
from urllib.parse import urlencode

# Load .env file for local development when python-dotenv is installed.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
except ImportError:
    pass

import requests
from flask import Flask, render_template, jsonify, request, redirect, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge

# Import encryption module
try:
    from encryption import encrypt_value, decrypt_value, ENCRYPTION_ENABLED
except ImportError:
    ENCRYPTION_ENABLED = False
    print("⚠ Warning: encryption module not available, using plain text")

# Import API key manager
from api_keys import api_manager

# Sensitive files that should never be accessible
SENSITIVE_FILES = [
    'api_keys.json', 'api_usage.json', 'accounts.txt', '.env',
    'encryption.py', 'api_keys.py', 'migrate_to_encrypted.py',
    '.env.backup', 'accounts.txt.backup'
]

# Decrypt .env values if they start with ENC:
def get_env(key, default=None):
    """Get env var, decrypt if it starts with ENC:"""
    value = os.environ.get(key, default)
    if value and ENCRYPTION_ENABLED and value.startswith('ENC:'):
        try:
            return decrypt_value(value)
        except Exception as e:
            print(f"⚠ Failed to decrypt {key}: {e}")
            return default
    return value

app = Flask(__name__)
_is_production = os.environ.get("FLASK_ENV", "development").lower() == "production"
_secret_key = get_env("FLASK_SECRET_KEY")
if not _secret_key:
    if _is_production:
        raise RuntimeError("FLASK_SECRET_KEY must be set in production")
    _secret_key = secrets.token_hex(32)
if _is_production and not ENCRYPTION_ENABLED:
    raise RuntimeError("Encryption must be configured in production")
app.secret_key = _secret_key
app.config["PERMANENT_SESSION_LIFETIME"] = int(os.environ.get("SESSION_LIFETIME_HOURS", "4")) * 3600

# ── Config ──────────────────────────────────────────────────────────
# Set via env vars, or edit defaults here
ADMIN_USER = get_env("ADMIN_USER", "admin")
ADMIN_PASS = get_env("ADMIN_PASS", "admin123")

# Rate limit settings (controlled via env)
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get("RATE_LIMIT_MAX_ATTEMPTS", "5"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_LOCKOUT_MINUTES", "15")) * 60
RATE_LIMIT_SLIDING_WINDOW = int(os.environ.get("RATE_LIMIT_SLIDING_WINDOW_MINUTES", "5")) * 60

ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "accounts.txt")
REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:5000/oauth/callback")
SCOPES_READ = "https://graph.microsoft.com/Mail.Read offline_access"
SCOPES_READWRITE = "https://graph.microsoft.com/Mail.ReadWrite offline_access"
MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "10")) * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

# ── Rate Limiter ────────────────────────────────────────────────────
_rate_limiter = {
    "attempts": {},   # ip -> list of timestamps
    "locked": {},     # ip -> unlock_time
    "lock": threading.Lock(),
}

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

def _cleanup_old_attempts(ip):
    now = time.time()
    if ip in _rate_limiter["attempts"]:
        _rate_limiter["attempts"][ip] = [
            t for t in _rate_limiter["attempts"][ip]
            if now - t < RATE_LIMIT_SLIDING_WINDOW
        ]

def check_rate_limit(ip):
    """Returns (allowed: bool, info: dict)"""
    if not RATE_LIMIT_ENABLED:
        return True, {"locked": False, "attempts_remaining": -1}

    with _rate_limiter["lock"]:
        now = time.time()

        # Check if locked
        if ip in _rate_limiter["locked"]:
            unlock_at = _rate_limiter["locked"][ip]
            if now < unlock_at:
                remaining = int(unlock_at - now)
                return False, {"locked": True, "retry_after": remaining}
            else:
                # Lockout expired, clear it
                del _rate_limiter["locked"][ip]
                _rate_limiter["attempts"].pop(ip, None)

        _cleanup_old_attempts(ip)
        attempts = _rate_limiter["attempts"].get(ip, [])
        return True, {
            "locked": False,
            "attempts_remaining": max(0, RATE_LIMIT_MAX_ATTEMPTS - len(attempts)),
        }

def record_failed_attempt(ip):
    if not RATE_LIMIT_ENABLED:
        return
    with _rate_limiter["lock"]:
        now = time.time()
        if ip not in _rate_limiter["attempts"]:
            _rate_limiter["attempts"][ip] = []
        _rate_limiter["attempts"][ip].append(now)
        _cleanup_old_attempts(ip)

        attempt_count = len(_rate_limiter["attempts"][ip])
        if attempt_count >= RATE_LIMIT_MAX_ATTEMPTS:
            _rate_limiter["locked"][ip] = now + RATE_LIMIT_WINDOW
            _rate_limiter["attempts"].pop(ip, None)

def record_success(ip):
    with _rate_limiter["lock"]:
        _rate_limiter["attempts"].pop(ip, None)
        _rate_limiter["locked"].pop(ip, None)

# ── Auth Decorator ──────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json or request.path.startswith("/api/"):
                return json_error("Unauthorized", 401, "unauthorized", redirect="/login")
            return redirect(url_for("login_page"))
        # Check session expiry
        if session.get("expires_at", 0) < time.time():
            session.clear()
            if request.is_json or request.path.startswith("/api/"):
                return json_error("Session expired", 401, "session_expired", redirect="/login")
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ── Response helpers ────────────────────────────────────────────────
def json_error(message, status=400, code=None, **extra):
    payload = {"success": False, "error": message}
    if code:
        payload["code"] = code
    payload.update(extra)
    return jsonify(payload), status


def json_success(**payload):
    payload.setdefault("success", True)
    return jsonify(payload)


# ── In-memory caches ────────────────────────────────────────────────
_accounts_cache = {"data": None, "mtime": 0, "unreadable_rows": [], "lock": threading.Lock()}
_token_cache = OrderedDict()  # key includes refresh token hash to avoid cross-account token reuse
_token_lock = threading.Lock()

REQUEST_TIMEOUT = 15  # seconds for all HTTP requests
# Microsoft access tokens are usually valid for 3600s; cache for 3300s to keep a 5-minute safety buffer.
TOKEN_CACHE_DURATION = 3300
TOKEN_CACHE_MAX_SIZE = int(os.environ.get("TOKEN_CACHE_MAX_SIZE", "256"))
OAUTH_STATE_TTL = 600
API_KEY_NAME_RE = re.compile(r"^[\w .@:+-]{1,80}$")

# Connection pooling
_http = requests.Session()
_adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,
    pool_maxsize=50,
    max_retries=3
)
_http.mount("https://", _adapter)
_http.mount("http://", _adapter)

# ── Encryption helpers ─────────────────────────────────────────────
def _decrypt_field(value):
    """Decrypt a field, unwrapping accidental nested encryption layers"""
    if not (ENCRYPTION_ENABLED and value):
        return value
    try:
        current = value
        for _ in range(100):
            if not (isinstance(current, str) and current.startswith('ENC:')):
                return current
            decrypted = decrypt_value(current)
            if decrypted == current:
                raise ValueError("Encrypted field could not be decrypted")
            current = decrypted
        if isinstance(current, str) and current.startswith('ENC:'):
            raise ValueError("Encrypted field has too many nested layers")
        return current
    except ValueError:
        raise
    except Exception as e:
        print(f"⚠ Decryption failed: {e}")
        return value

def _encrypt_field(value):
    """Encrypt a single field if encryption is enabled"""
    if ENCRYPTION_ENABLED and value:
        try:
            plaintext = _decrypt_field(value)
            return encrypt_value(plaintext)
        except ValueError:
            raise
        except Exception as e:
            print(f"⚠ Encryption failed: {e}")
            return value
    return value

# ── Account helpers ─────────────────────────────────────────────────
def load_accounts():
    with _accounts_cache["lock"]:
        if not os.path.exists(ACCOUNTS_FILE):
            _accounts_cache["data"] = []
            _accounts_cache["mtime"] = 0
            _accounts_cache["unreadable_rows"] = []
            return []
        mtime = os.path.getmtime(ACCOUNTS_FILE)
        if _accounts_cache["data"] is not None and mtime == _accounts_cache["mtime"]:
            return _accounts_cache["data"]

        # Load all accounts first
        all_accounts = []
        unreadable_rows = []
        with open(ACCOUNTS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split("----")
                if len(parts) == 4:
                    try:
                        all_accounts.append({
                            "email": _decrypt_field(parts[0]),
                            "password": _decrypt_field(parts[1]),
                            "client_id": _decrypt_field(parts[2]),
                            "refresh_token": _decrypt_field(parts[3]),
                        })
                    except ValueError as e:
                        unreadable_rows.append(line)
                        print(f"⚠ Skipping unreadable encrypted account row: {e}")

        # Deduplicate by email (keep first occurrence)
        seen_emails = set()
        accounts = []
        duplicates = []
        for acc in all_accounts:
            email_lower = acc["email"].lower()
            if email_lower not in seen_emails:
                seen_emails.add(email_lower)
                accounts.append(acc)
            else:
                duplicates.append(acc["email"])

        if duplicates:
            print(f"[WARNING] Found {len(duplicates)} duplicate account(s): {', '.join(duplicates[:5])}{'...' if len(duplicates) > 5 else ''}")

        _accounts_cache["data"] = accounts
        _accounts_cache["mtime"] = mtime
        _accounts_cache["unreadable_rows"] = unreadable_rows
        return accounts

def invalidate_accounts_cache():
    with _accounts_cache["lock"]:
        _accounts_cache["data"] = None
        _accounts_cache["mtime"] = 0
        _accounts_cache["unreadable_rows"] = []

def save_accounts(accounts, already_deduplicated=False):
    if already_deduplicated:
        unique = accounts
    else:
        seen_emails = set()
        unique = []
        for a in accounts:
            email_lower = a["email"].lower()
            if email_lower not in seen_emails:
                seen_emails.add(email_lower)
                unique.append(a)

    rows = []
    for a in unique:
        email = _encrypt_field(a['email'])
        password = _encrypt_field(a['password'])
        client_id = _encrypt_field(a['client_id'])
        refresh_token = _encrypt_field(a['refresh_token'])
        rows.append(f"{email}----{password}----{client_id}----{refresh_token}")

    with _accounts_cache["lock"]:
        rows.extend(_accounts_cache.get("unreadable_rows", []))

    with open(ACCOUNTS_FILE, "w") as f:
        if ENCRYPTION_ENABLED:
            f.write("# ENCRYPTED - DO NOT EDIT MANUALLY\n")
        for row in rows:
            f.write(f"{row}\n")
    invalidate_accounts_cache()

# ── Microsoft API helpers ───────────────────────────────────────────
def _token_cache_key(client_id, refresh_token, scopes):
    refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
    return (client_id, refresh_hash, scopes)


def _cleanup_token_cache(now):
    expired = [key for key, value in _token_cache.items() if value["expires"] <= now]
    for key in expired:
        del _token_cache[key]
    while len(_token_cache) > TOKEN_CACHE_MAX_SIZE:
        _token_cache.popitem(last=False)


def get_access_token(client_id, refresh_token, scopes=None):
    if scopes is None:
        scopes = SCOPES_READ
    cache_key = _token_cache_key(client_id, refresh_token, scopes)
    now = time.time()
    with _token_lock:
        _cleanup_token_cache(now)
        cached = _token_cache.get(cache_key)
        if cached and cached["expires"] > now + 60:
            _token_cache.move_to_end(cache_key)
            return cached["token"]
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "scope": scopes,
    }
    try:
        resp = _http.post(token_url, data=data, timeout=REQUEST_TIMEOUT)
    except (requests.Timeout, requests.ConnectionError):
        return None
    if resp.status_code != 200:
        return None
    result = resp.json()
    token = result.get("access_token")
    if token:
        expires_in = min(int(result.get("expires_in", TOKEN_CACHE_DURATION)), TOKEN_CACHE_DURATION)
        with _token_lock:
            _token_cache[cache_key] = {"token": token, "expires": now + expires_in}
            _token_cache.move_to_end(cache_key)
            _cleanup_token_cache(now)
    return token


def clear_token_cache(client_id=None):
    with _token_lock:
        if client_id is None:
            _token_cache.clear()
        else:
            keys_to_remove = [k for k in _token_cache if k[0] == client_id]
            for k in keys_to_remove:
                del _token_cache[k]


def fetch_inbox(access_token, top=50):
    url = f"https://graph.microsoft.com/v1.0/me/messages?$top={top}&$orderby=receivedDateTime%20desc&$select=subject,from,receivedDateTime,bodyPreview,isRead,id"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        resp = _http.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except (requests.Timeout, requests.ConnectionError):
        return None
    if resp.status_code != 200:
        return None
    return resp.json().get("value", [])


def fetch_message(access_token, message_id):
    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}?$select=subject,from,toRecipients,receivedDateTime,body"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        resp = _http.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except (requests.Timeout, requests.ConnectionError):
        return None
    if resp.status_code != 200:
        return None
    return resp.json()


def fetch_inbox_for_account(account, top=50):
    token = get_access_token(account["client_id"], account["refresh_token"])
    if not token:
        return None
    return fetch_inbox(token, top)


def fetch_message_for_account(account, message_id):
    token = get_access_token(account["client_id"], account["refresh_token"])
    if not token:
        return None
    return fetch_message(token, message_id)


def search_messages(account, query, top=25):
    token = get_access_token(account["client_id"], account["refresh_token"])
    if not token:
        return None
    params = urlencode({
        "$search": f'"{query}"',
        "$top": top,
        "$select": "subject,from,receivedDateTime,bodyPreview,isRead,id",
    })
    url = f"https://graph.microsoft.com/v1.0/me/messages?{params}"
    headers = {
        "Authorization": f"Bearer {token}",
        "ConsistencyLevel": "eventual",
    }
    try:
        resp = _http.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except (requests.Timeout, requests.ConnectionError):
        return None
    if resp.status_code != 200:
        return None
    return resp.json().get("value", [])

# ── Auth Routes ─────────────────────────────────────────────────────
@app.route("/login")
def login_page():
    if session.get("authenticated") and session.get("expires_at", 0) > time.time():
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = get_client_ip()

    # Check rate limit
    allowed, info = check_rate_limit(ip)
    if not allowed:
        return json_error(
            f"Too many failed attempts. Try again in {info['retry_after']}s.",
            429,
            "rate_limited",
            locked=True,
            retryAfter=info["retry_after"],
        )

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    # Timing-safe comparison
    if secrets.compare_digest(username, ADMIN_USER) and secrets.compare_digest(password, ADMIN_PASS):
        session.permanent = True
        session["authenticated"] = True
        session["login_ip"] = ip
        session["expires_at"] = time.time() + app.config["PERMANENT_SESSION_LIFETIME"]
        record_success(ip)
        return json_success()

    record_failed_attempt(ip)
    allowed2, info2 = check_rate_limit(ip)
    resp_data = {"error": "Invalid username or password"}
    if info2.get("locked"):
        resp_data["locked"] = True
        resp_data["retryAfter"] = info2["retry_after"]
        resp_data["error"] = f"Too many failed attempts. Locked for {info2['retry_after']}s."
    else:
        resp_data["attemptsRemaining"] = info2.get("attempts_remaining", 0)
    return json_error(
        resp_data["error"],
        401,
        "invalid_credentials",
        **{k: v for k, v in resp_data.items() if k != "error"}
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# ── Protected Routes ────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/api/accounts")
@login_required
def api_accounts():
    accounts = load_accounts()
    return json_success(accounts=[{"email": a["email"]} for a in accounts])

@app.route("/api/inbox/<int:account_index>")
@login_required
def api_inbox(account_index):
    accounts = load_accounts()
    if account_index < 0 or account_index >= len(accounts):
        return json_error("Invalid account index", 400, "invalid_account_index")
    account = accounts[account_index]
    token = get_access_token(account["client_id"], account["refresh_token"])
    if not token:
        return json_error("Failed to get access token", 502, "microsoft_token_failed")
    messages = fetch_inbox(token)
    if messages is None:
        return json_error("Failed to fetch inbox", 502, "microsoft_inbox_failed")
    return json_success(messages=messages)

@app.route("/api/message/<int:account_index>/<message_id>")
@login_required
def api_message(account_index, message_id):
    accounts = load_accounts()
    if account_index < 0 or account_index >= len(accounts):
        return json_error("Invalid account index", 400, "invalid_account_index")
    account = accounts[account_index]
    token = get_access_token(account["client_id"], account["refresh_token"])
    if not token:
        return json_error("Failed to get access token", 502, "microsoft_token_failed")
    message = fetch_message(token, message_id)
    if message is None:
        return json_error("Failed to fetch message", 502, "microsoft_message_failed")
    return json_success(message=message)

@app.route("/api/mark-read/<int:account_index>/<message_id>", methods=["PATCH"])
@login_required
def api_mark_read(account_index, message_id):
    accounts = load_accounts()
    if account_index < 0 or account_index >= len(accounts):
        return json_error("Invalid account index", 400, "invalid_account_index")
    account = accounts[account_index]

    token = get_access_token(account["client_id"], account["refresh_token"], SCOPES_READWRITE)
    need_reauth = False
    if not token:
        token = get_access_token(account["client_id"], account["refresh_token"], SCOPES_READ)
        need_reauth = True

    if not token:
        return json_error("Failed to get access token", 502, "microsoft_token_failed")

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return json_error("Request body must be a JSON object", 400, "invalid_json")
    is_read = data.get("isRead", True)
    url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        resp = _http.patch(url, headers=headers, json={"isRead": is_read}, timeout=REQUEST_TIMEOUT)
    except (requests.Timeout, requests.ConnectionError):
        return json_error("Request timed out", 504, "request_timeout")
    if resp.status_code == 403 or resp.status_code == 401:
        return json_error("Need re-authorization", 403, "need_reauth", needReauth=True)
    if resp.status_code != 200:
        return json_error("Failed to update read status", 502, "microsoft_update_failed")
    return json_success(isRead=is_read, needReauth=need_reauth)

@app.route("/api/upload-accounts", methods=["POST"])
@login_required
def api_upload_accounts():
    if "file" not in request.files:
        return json_error("No file uploaded", 400, "missing_file")
    file = request.files["file"]
    if file.filename == "":
        return json_error("No file selected", 400, "missing_filename")

    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_UPLOAD_SIZE:
        return json_error(f"File too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)", 413, "file_too_large")

    mode = request.form.get("mode", "append")
    content = file.read().decode("utf-8", errors="replace").strip()
    if not content:
        return json_error("File is empty", 400, "empty_file")

    existing = load_accounts()
    existing_emails = {a["email"].lower() for a in existing}

    new_accounts = []
    errors = []
    seen_emails = set()
    for i, line in enumerate(content.split("\n"), 1):
        line = line.strip()
        if not line:
            continue
        parts = line.split("----")
        if len(parts) == 4:
            try:
                email = _decrypt_field(parts[0].strip())
                password = _decrypt_field(parts[1].strip())
                client_id = _decrypt_field(parts[2].strip())
                refresh_token = _decrypt_field(parts[3].strip())
            except ValueError:
                errors.append(f"Line {i}: encrypted account could not be decrypted, skipped")
                continue
            if email.lower() in existing_emails:
                errors.append(f"Line {i}: {email} already exists, skipped")
                continue
            if email.lower() in seen_emails:
                errors.append(f"Line {i}: {email} duplicate in file, skipped")
                continue
            seen_emails.add(email.lower())
            new_accounts.append({
                "email": email,
                "password": password,
                "client_id": client_id,
                "refresh_token": refresh_token,
            })
        else:
            errors.append(f"Line {i}: invalid format (expected 4 fields separated by '----')")

    if not new_accounts:
        return json_error("No valid accounts found in file", 400, "no_valid_accounts", details=errors)

    if mode == "replace":
        final = new_accounts
    else:
        final = existing + new_accounts

    save_accounts(final, already_deduplicated=True)
    return json_success(
        message=f"{'Added' if mode == 'append' else 'Loaded'} {len(new_accounts)} account(s)",
        added=len(new_accounts),
        total=len(final),
        errors=errors,
    )

@app.route("/api/delete-account/<int:account_index>", methods=["DELETE"])
@login_required
def api_delete_account(account_index):
    accounts = load_accounts()
    if account_index < 0 or account_index >= len(accounts):
        return json_error("Invalid account index", 400, "invalid_account_index")
    removed = accounts.pop(account_index)
    save_accounts(accounts, already_deduplicated=True)
    clear_token_cache(removed["client_id"])
    return json_success(
        message=f"Deleted {removed['email']}",
        email=removed["email"],
        remaining=len(accounts),
    )

@app.route("/api/check-duplicates", methods=["GET"])
@login_required
def api_check_duplicates():
    """Check for duplicate emails in accounts file"""
    if not os.path.exists(ACCOUNTS_FILE):
        return json_success(duplicates=[], total=0)

    # Read all accounts without deduplication
    all_accounts = []
    with open(ACCOUNTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split("----")
            if len(parts) == 4:
                try:
                    all_accounts.append({
                        "email": _decrypt_field(parts[0]),
                        "password": parts[1],
                        "client_id": parts[2],
                        "refresh_token": parts[3],
                    })
                except ValueError as e:
                    print(f"⚠ Skipping unreadable encrypted account row: {e}")

    # Find duplicates
    email_counts = {}
    for acc in all_accounts:
        email_lower = acc["email"].lower()
        if email_lower not in email_counts:
            email_counts[email_lower] = []
        email_counts[email_lower].append(acc["email"])

    duplicates = []
    for email_lower, emails in email_counts.items():
        if len(emails) > 1:
            duplicates.append({
                "email": emails[0],
                "count": len(emails),
            })

    return json_success(
        duplicates=duplicates,
        total=len(all_accounts),
        unique=len(email_counts),
        duplicate_count=sum(d["count"] - 1 for d in duplicates),
    )

@app.route("/api/clean-duplicates", methods=["POST"])
@login_required
def api_clean_duplicates():
    """Remove duplicate accounts, keeping only the first occurrence"""
    if not os.path.exists(ACCOUNTS_FILE):
        return json_success(message="No accounts file found", removed=0)

    # Read all accounts without deduplication
    all_accounts = []
    unreadable_rows = []
    with open(ACCOUNTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split("----")
            if len(parts) == 4:
                try:
                    all_accounts.append({
                        "email": _decrypt_field(parts[0]),
                        "password": _decrypt_field(parts[1]),
                        "client_id": _decrypt_field(parts[2]),
                        "refresh_token": _decrypt_field(parts[3]),
                    })
                except ValueError as e:
                    unreadable_rows.append(line)
                    print(f"⚠ Skipping unreadable encrypted account row: {e}")

    original_count = len(all_accounts)

    # Deduplicate (keep first occurrence)
    seen_emails = set()
    unique = []
    removed_emails = []
    for acc in all_accounts:
        email_lower = acc["email"].lower()
        if email_lower not in seen_emails:
            seen_emails.add(email_lower)
            unique.append(acc)
        else:
            removed_emails.append(acc["email"])

    if len(unique) == original_count:
        return json_success(
            message="No duplicates found",
            removed=0,
            remaining=original_count,
        )

    # Save cleaned accounts
    with _accounts_cache["lock"]:
        _accounts_cache["unreadable_rows"] = unreadable_rows
    save_accounts(unique, already_deduplicated=True)

    return json_success(
        message=f"Removed {len(removed_emails)} duplicate account(s)",
        removed=len(removed_emails),
        remaining=len(unique),
        removed_emails=removed_emails[:20],
    )

@app.route("/api/authorize-url/<int:account_index>")
@login_required
def api_authorize_url(account_index):
    accounts = load_accounts()
    if account_index < 0 or account_index >= len(accounts):
        return json_error("Invalid account index", 400, "invalid_account_index")
    account = accounts[account_index]
    state = secrets.token_urlsafe(32)
    session.setdefault("oauth_states", {})
    oauth_states = session["oauth_states"]
    oauth_states[state] = {"account_index": account_index, "expires": time.time() + OAUTH_STATE_TTL}
    session["oauth_states"] = oauth_states
    params = urlencode({
        "client_id": account["client_id"],
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES_READWRITE,
        "state": state,
        "login_hint": account["email"],
    })
    url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}"
    return json_success(url=url)

# oauth_callback is NOT login_required (it's called from Microsoft popup)
@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state", "")
    error = request.args.get("error")

    oauth_states = session.get("oauth_states", {})
    state_data = oauth_states.pop(state, None)
    session["oauth_states"] = oauth_states
    if not state_data or state_data.get("expires", 0) < time.time():
        return """
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>Error</h2><p>Invalid authorization state</p>
            <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>""", 400
    account_index = state_data["account_index"]

    if error:
        safe_error = html.escape(error)
        return f"""
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>Authorization Failed</h2><p>{safe_error}</p>
            <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>""", 400

    if not code:
        return """
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>Error</h2><p>Missing authorization code</p>
            <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>""", 400

    accounts = load_accounts()
    if account_index < 0 or account_index >= len(accounts):
        return """
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>Error</h2><p>Invalid account</p>
            <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>"""

    account = accounts[account_index]
    try:
        resp = _http.post("https://login.microsoftonline.com/common/oauth2/v2.0/token", data={
            "client_id": account["client_id"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }, timeout=REQUEST_TIMEOUT)
    except (requests.Timeout, requests.ConnectionError):
        return """
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>Timeout</h2><p>Authorization request timed out. Please try again.</p>
            <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>"""

    if resp.status_code != 200:
        safe_response = html.escape(resp.text)
        return f"""
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>Token Error</h2><pre>{safe_response}</pre>
            <script>setTimeout(()=>window.close(),5000)</script>
        </body></html>""", 502

    new_refresh_token = resp.json().get("refresh_token")
    if new_refresh_token:
        accounts[account_index]["refresh_token"] = new_refresh_token
        save_accounts(accounts, already_deduplicated=True)
        clear_token_cache(account["client_id"])
        return """
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2 style="color:#3fb950">✓ Authorized Successfully!</h2>
            <p>Refresh token updated. You can close this window.</p>
            <script>if(window.opener)window.opener.postMessage({type:'auth-success'},'*');setTimeout(()=>window.close(),3000)</script>
        </body></html>"""
    else:
        return """
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:sans-serif;text-align:center;padding:60px">
            <h2>No refresh token received</h2>
            <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>"""


# ── API Key Verification Decorator ──────────────────────────────────
def require_api_key(f):
    """Decorator to verify API key for agent endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return json_error("Missing API key", 401, "missing_api_key")

        result = api_manager.verify_key(api_key, request.method)
        if not result['valid']:
            status_code = 429 if result.get('rate_limited') else 401
            return json_error(result['error'], status_code, "rate_limited" if result.get('rate_limited') else "invalid_api_key")

        # Add key info to request context
        request.api_key_data = result['key_data']
        return f(*args, **kwargs)
    return decorated

# ── Agent API Endpoints (v1/agent) ──────────────────────────────────
@app.route("/api/v1/agent/accounts")
@require_api_key
def agent_accounts():
    """List all accounts"""
    accounts = load_accounts()
    return json_success(
        count=len(accounts),
        accounts=[{"email": a["email"]} for a in accounts]
    )

@app.route("/api/v1/agent/inbox/<email>")
@require_api_key
def agent_inbox(email):
    """Get inbox for specific email"""
    accounts = load_accounts()
    account = next((a for a in accounts if a["email"].lower() == email.lower()), None)

    if not account:
        return json_error("Account not found", 404, "account_not_found")

    messages = fetch_inbox_for_account(account)
    if messages is None:
        return json_error("Failed to fetch inbox", 502, "microsoft_inbox_failed")

    return json_success(
        email=email,
        count=len(messages),
        messages=messages
    )

@app.route("/api/v1/agent/message/<email>/<message_id>")
@require_api_key
def agent_message(email, message_id):
    """Get specific message"""
    accounts = load_accounts()
    account = next((a for a in accounts if a["email"].lower() == email.lower()), None)

    if not account:
        return json_error("Account not found", 404, "account_not_found")

    message = fetch_message_for_account(account, message_id)
    if message is None:
        return json_error("Failed to fetch message", 502, "microsoft_message_failed")

    return json_success(message=message)

@app.route("/api/v1/agent/search/<email>")
@require_api_key
def agent_search(email):
    """Search emails"""
    accounts = load_accounts()
    account = next((a for a in accounts if a["email"].lower() == email.lower()), None)

    if not account:
        return json_error("Account not found", 404, "account_not_found")

    query = request.args.get('q', '')
    if not query:
        return json_error("Missing search query (q parameter)", 400, "missing_query")

    messages = search_messages(account, query)
    if messages is None:
        return json_error("Failed to search messages", 502, "microsoft_search_failed")

    return json_success(
        email=email,
        query=query,
        count=len(messages),
        messages=messages
    )

# ── API Key Management Endpoints ────────────────────────────────────
@app.route("/api-keys")
@login_required
def api_keys_page():
    """API keys management page"""
    return render_template("api_keys.html")

@app.route("/api/keys")
@login_required
def list_api_keys():
    """List all API keys (metadata only)"""
    keys = api_manager.list_keys()
    return json_success(count=len(keys), keys=keys)

@app.route("/api/keys/generate", methods=["POST"])
@login_required
def generate_api_key():
    """Generate new API key"""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Request body must be a JSON object", 400, "invalid_json")
    name = data.get('name', '').strip()
    permission = data.get('permission', 'read-only')
    expires_days = data.get('expires_days')
    rate_limit = data.get('rate_limit', '60/min')

    if not name:
        return json_error("Name is required", 400, "name_required")
    if not API_KEY_NAME_RE.fullmatch(name):
        return json_error("Name must be 1-80 chars and contain only letters, numbers, spaces, and ._@:+-", 400, "invalid_name")

    if permission not in ['read-only', 'read-write', 'admin']:
        return json_error("Invalid permission level", 400, "invalid_permission")

    if rate_limit not in api_manager.RATE_LIMITS:
        return json_error("Invalid rate limit", 400, "invalid_rate_limit")

    if expires_days is not None:
        try:
            expires_days = int(expires_days)
            if expires_days <= 0 or expires_days > 3650:
                return json_error("expires_days must be between 1 and 3650", 400, "invalid_expires_days")
        except (TypeError, ValueError):
            return json_error("expires_days must be a positive integer", 400, "invalid_expires_days")

    try:
        key_info = api_manager.generate_key(name, permission, expires_days, rate_limit)
    except ValueError as e:
        return json_error(str(e), 400, "invalid_api_key_options")

    return json_success(
        message="API key generated successfully",
        key=key_info['key'],
        name=key_info['name'],
        permission=key_info['permission'],
        expires_at=key_info['expires_at'],
        rate_limit=key_info['rate_limit']
    )

@app.route("/api/keys/<api_key>/revoke", methods=["POST"])
@login_required
def revoke_api_key(api_key):
    """Revoke an API key"""
    try:
        if api_manager.revoke_key(api_key):
            return json_success(message="API key revoked successfully")
        return json_error("API key not found", 404, "api_key_not_found")
    except Exception as e:
        return json_error(str(e), 500, "api_key_revoke_failed")

@app.route("/api/keys/<api_key>/stats")
@login_required
def api_key_stats(api_key):
    """Get usage stats for a key"""
    stats = api_manager.get_key_stats(api_key)
    if not stats:
        return json_error("API key not found", 404, "api_key_not_found")

    return json_success(stats=stats)

@app.errorhandler(RequestEntityTooLarge)
def payload_too_large(e):
    return json_error(f"File too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)", 413, "file_too_large")

# ── Handle 401 for frontend fetch calls ─────────────────────────────
@app.errorhandler(401)
def unauthorized(e):
    if request.path.startswith("/api/"):
        return json_error("Unauthorized", 401, "unauthorized", redirect="/login")
    return redirect(url_for("login_page"))


if __name__ == "__main__":
    debug = (not _is_production) and os.environ.get("FLASK_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", debug=debug, port=5000)
