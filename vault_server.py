#!/usr/bin/env python3
import os, sys, secrets, logging
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from flask import Flask, request, jsonify, make_response, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import vault_core as core

MASTER_KEY = os.environ.get("VAULT_MASTER_KEY", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
HOST       = os.environ.get("VAULT_HOST", "127.0.0.1")
PORT       = int(os.environ.get("VAULT_PORT", "7777"))
JWT_EXPIRE = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))
ENV_NAME   = os.environ.get("VAULT_ENV_NAME", "local")
IS_SECURE  = ENV_NAME != "local"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vault.server")

startup_warnings = core.check_env_file_permissions()
for w in startup_warnings:
    log.warning(w)

app = Flask(__name__)
app.config["SECRET_KEY"] = JWT_SECRET or secrets.token_hex(32)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"], storage_uri="memory://")

def get_fernet():
    if not MASTER_KEY:
        raise RuntimeError("VAULT_MASTER_KEY not set")
    return Fernet(MASTER_KEY.encode())

def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

def require_csrf(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in CSRF_SAFE_METHODS:
            return f(*args, **kwargs)
        cookie_token = request.cookies.get("csrf_token", "")
        header_token = request.headers.get("X-CSRF-Token", "")
        if not cookie_token or not secrets.compare_digest(cookie_token, header_token):
            core.audit("csrf_rejected", "unknown", _ip(), request.path, success=False)
            return jsonify({"error": "CSRF validation failed"}), 403
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("vault_session")
        if not token:
            return jsonify({"error": "Admin session required"}), 401
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid session"}), 401
        return f(*args, **kwargs)
    return wrapper

def require_machine_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            token = request.headers.get("X-Machine-Token", "")
        if not token:
            core.audit("machine_auth", "unknown", _ip(), "missing token", success=False)
            return jsonify({"error": "Machine token required"}), 401
        key_name = kwargs.get("name", "*")
        ok, reason = core.verify_machine_token(get_fernet(), token, _ip(), key_name)
        if not ok:
            core.audit("machine_auth", "machine", _ip(), reason, success=False)
            return jsonify({"error": "Unauthorized"}), 401
        core.audit("machine_key_access", "machine", _ip(), key_name)
        return f(*args, **kwargs)
    return wrapper

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none';"
    )
    if IS_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

@app.get("/health")
def health():
    meta = core.load_meta()
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat(),
                    "totp_enabled": meta.get("totp_enabled", False), "env": ENV_NAME,
                    "vault_exists": core.VAULT_FILE.exists()})

@app.post("/admin/login")
@limiter.limit("10 per minute")
def admin_login():
    body = request.get_json(silent=True) or {}
    password = body.get("password", "")
    totp_code = body.get("totp", "")
    meta = core.load_meta()
    stored_hash = meta.get("admin_password_hash")
    if not stored_hash:
        return jsonify({"error": "Vault not initialized — run setup.py first"}), 403
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ph = PasswordHasher()
    try:
        ph.verify(stored_hash, password)
    except VerifyMismatchError:
        core.audit("admin_login", "admin", _ip(), "wrong password", success=False)
        return jsonify({"error": "Invalid credentials"}), 401
    if core.totp_enabled():
        if not totp_code:
            return jsonify({"error": "TOTP code required", "totp_required": True}), 401
        if not core.verify_totp(totp_code):
            core.audit("admin_login", "admin", _ip(), "bad TOTP", success=False)
            return jsonify({"error": "Invalid TOTP code"}), 401
    payload = {"sub": "admin", "iat": datetime.now(timezone.utc),
               "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE),
               "jti": secrets.token_hex(16)}
    session_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    csrf_token = secrets.token_urlsafe(32)
    core.audit("admin_login", "admin", _ip(), "success")
    resp = make_response(jsonify({"ok": True, "expires_in": JWT_EXPIRE * 60}))
    resp.set_cookie("vault_session", session_token, httponly=True, samesite="Strict",
                    secure=IS_SECURE, max_age=JWT_EXPIRE * 60, path="/admin")
    resp.set_cookie("csrf_token", csrf_token, httponly=False, samesite="Strict",
                    secure=IS_SECURE, max_age=JWT_EXPIRE * 60, path="/admin")
    return resp

@app.post("/admin/logout")
def admin_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("vault_session", path="/admin")
    resp.delete_cookie("csrf_token", path="/admin")
    return resp

@app.get("/admin/keys")
@require_admin
def admin_list_keys():
    fernet = get_fernet()
    vault  = core.load_vault(fernet)
    keys   = list(vault.keys())
    ages   = core.get_key_ages(keys)
    stale  = core.get_stale_keys(keys)
    stale_names = {s["name"] for s in stale}
    result = [{"name": k, "stale": k in stale_names, **ages.get(k, {})} for k in keys]
    return jsonify({"keys": result, "count": len(keys), "stale_count": len(stale)})

@app.get("/admin/keys/<n>")
@require_admin
def admin_get_key(n: str):
    name = n
    vault = core.load_vault(get_fernet())
    if name not in vault:
        return jsonify({"error": f"Key '{name}' not found"}), 404
    core.audit("admin_key_view", "admin", _ip(), name)
    ages = core.get_key_ages([name])
    return jsonify({"name": name, "value": vault[name], **ages.get(name, {})})

@app.post("/admin/keys/<n>")
@require_admin
@require_csrf
def admin_set_key(name: str):
    body  = request.get_json(silent=True) or {}
    value = body.get("value")
    if not value:
        return jsonify({"error": "Missing 'value'"}), 400
    fernet = get_fernet()
    vault  = core.load_vault(fernet)
    is_new = name not in vault
    vault[name] = value
    core.save_vault(fernet, vault)
    core.track_key_write(name, is_new)
    core.write_backup(fernet)
    core.audit(f"admin_key_{'created' if is_new else 'updated'}", "admin", _ip(), name)
    return jsonify({"status": "created" if is_new else "updated", "name": name})

@app.delete("/admin/keys/<n>")
@require_admin
@require_csrf
def admin_delete_key(name: str):
    fernet = get_fernet()
    vault  = core.load_vault(fernet)
    if name not in vault:
        return jsonify({"error": f"Key '{name}' not found"}), 404
    del vault[name]
    core.save_vault(fernet, vault)
    core.track_key_delete(name)
    core.write_backup(fernet)
    core.audit("admin_key_deleted", "admin", _ip(), name)
    return jsonify({"status": "deleted", "name": name})

@app.get("/admin/tokens")
@require_admin
def admin_list_tokens():
    tokens = core.load_tokens(get_fernet())
    result = [{**entry, "token_hash": thash[:16] + "..."} for thash, entry in tokens.items()]
    return jsonify({"tokens": result})

@app.post("/admin/tokens")
@require_admin
@require_csrf
def admin_mint_token():
    body = request.get_json(silent=True) or {}
    label = body.get("label", "unnamed")
    scope = body.get("scope", ["*"])
    allowed_ips = body.get("allowed_ips", [])
    raw = core.mint_token(get_fernet(), label, scope, allowed_ips)
    core.audit("token_minted", "admin", _ip(), label)
    return jsonify({"token": raw, "label": label, "scope": scope,
                    "warning": "Store this token now — it will not be shown again."})

@app.delete("/admin/tokens/<token_hash>")
@require_admin
@require_csrf
def admin_revoke_token(token_hash: str):
    ok = core.revoke_token(get_fernet(), token_hash)
    if not ok:
        return jsonify({"error": "Token not found"}), 404
    core.audit("token_revoked", "admin", _ip(), token_hash[:16])
    return jsonify({"status": "revoked"})

@app.get("/admin/audit")
@require_admin
def admin_audit():
    limit = min(int(request.args.get("limit", 200)), 1000)
    return jsonify({"entries": core.read_audit(limit)})

@app.get("/admin/backups")
@require_admin
def admin_list_backups():
    return jsonify({"backups": core.list_backups()})

@app.post("/admin/backups")
@require_admin
@require_csrf
def admin_trigger_backup():
    dest = core.write_backup(get_fernet())
    core.audit("manual_backup", "admin", _ip(), str(dest))
    return jsonify({"status": "ok", "file": dest.name})

@app.post("/admin/backups/<filename>/restore")
@require_admin
@require_csrf
def admin_restore_backup(filename: str):
    ok = core.restore_backup(get_fernet(), filename)
    if not ok:
        return jsonify({"error": "Restore failed — file not found or corrupt"}), 400
    core.audit("backup_restored", "admin", _ip(), filename)
    return jsonify({"status": "restored", "from": filename})

@app.post("/admin/totp/setup")
@require_admin
@require_csrf
def admin_totp_setup():
    import qrcode, io, base64
    secret, url = core.setup_totp("OpenClaw Vault")
    qr  = qrcode.make(url)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode()
    core.audit("totp_setup", "admin", _ip())
    return jsonify({"secret": secret, "otpauth": url, "qr_base64": img_b64})

@app.delete("/admin/totp")
@require_admin
@require_csrf
def admin_totp_disable():
    meta = core.load_meta()
    meta["totp_enabled"] = False
    meta.pop("totp_secret", None)
    core.save_meta(meta)
    core.audit("totp_disabled", "admin", _ip())
    return jsonify({"status": "totp disabled"})

@app.get("/api/keys")
@require_machine_token
def api_list_keys():
    vault = core.load_vault(get_fernet())
    return jsonify({"keys": list(vault.keys())})

@app.get("/api/keys/<n>")
@require_machine_token
def api_get_key(n: str):
    name = n
    vault = core.load_vault(get_fernet())
    if name not in vault:
        return jsonify({"error": f"Key '{name}' not found"}), 404
    return jsonify({"name": name, "value": vault[name]})

@app.get("/")
def admin_ui():
    ui_path = os.path.join(os.path.dirname(__file__), "ui", "index.html")
    if os.path.exists(ui_path):
        return send_file(ui_path)
    return "<h2>UI not found. Run setup.py first.</h2>", 404

if __name__ == "__main__":
    if not MASTER_KEY:
        sys.exit("ERROR: VAULT_MASTER_KEY not set. Run setup.py first.")
    if not JWT_SECRET:
        sys.exit("ERROR: JWT_SECRET not set. Run setup.py first.")
    log.warning("Running with Flask dev server. Use gunicorn for production.")
    app.run(host=HOST, port=PORT, debug=False)
