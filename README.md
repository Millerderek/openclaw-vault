cd /root/APIKeys
cat > README.md << 'EOF'
# openclaw-vault

Encrypted key vault and credential manager for OpenClaw AI agent deployments.

Stores API keys in a Fernet-encrypted vault, injects them at boot time into OpenClaw's runtime config, and provides a CLI for day-to-day key management — no plaintext secrets in config files or environment variables.

---

## Features

- **AES-256 encrypted vault** — keys stored in `/etc/openclaw/vault.enc`
- **Flask API** — machine token auth, CSRF protection, httponly cookies
- **TOTP + admin password** — two-factor admin access
- **Boot injection** — pulls keys from vault and writes runtime config before OpenClaw starts
- **Migration tool** — imports from `auth-profiles.json` and `openclaw.json`
- **`clawvault` CLI** — interactive menu for adding, rotating, deleting, and exporting keys
- **Audit log** — every key access recorded
- **Automatic backups** — encrypted backup on every write
- **Systemd service** — vault starts on boot, chained to OpenClaw

---

## Requirements

- Python 3.11+
- Debian/Ubuntu VPS (tested on Debian 12)
- OpenClaw installed at `~/.openclaw/`

---

## Installation
```bash
git clone https://github.com/Millerderek/openclaw-vault
cd openclaw-vault
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python3 setup.py
```

Setup will generate encryption keys, configure TOTP, and write `/etc/openclaw/vault.env`.

---

## Migrate existing credentials
```bash
venv/bin/python3 migrate_to_vault.py --dry-run
venv/bin/python3 migrate_to_vault.py
```

Scans `auth-profiles.json` and `openclaw.json`. Rewrites `openclaw.json` as a `__VAULT:KEY__` template. `auth-profiles.json` is left intact.

---

## Boot injection
```bash
venv/bin/python3 openclaw_boot_inject.py --dry-run
venv/bin/python3 openclaw_boot_inject.py --write
OPENCLAW_CONFIG_PATH=~/.openclaw/openclaw.runtime.json openclaw gateway start
```

---

## Systemd
```bash
cp openclaw-vault.service /etc/systemd/system/
systemctl enable --now openclaw-vault
```

---

## clawvault CLI
```bash
chmod +x clawvault
ln -sf $(pwd)/clawvault /usr/local/bin/clawvault
clawvault
```

Interactive menu: list, add, rotate, delete, show, export.

---

## Security notes

- `/etc/openclaw/vault.env` contains the master key — `chmod 600`, root only
- `vault.enc`, `*.env`, and `*.log` excluded from git
- Machine tokens IP-restricted to `127.0.0.1`
- Vault UI binds to `localhost:7777` — use SSH tunnel for browser access

---

## Files

| File | Purpose |
|------|---------|
| `vault_core.py` | Encryption, token management, audit logging |
| `vault_server.py` | Flask REST API + admin UI backend |
| `setup.py` | First-run setup wizard |
| `migrate_to_vault.py` | Import credentials from OpenClaw config files |
| `openclaw_boot_inject.py` | Boot-time secret injection |
| `clawvault` | Interactive CLI |
| `openclaw-agent.service` | Systemd unit |
| `ui/index.html` | Single-page admin UI |
EOF

git add README.md
git commit -m "Add README"
git push
