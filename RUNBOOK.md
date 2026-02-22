# OpenClaw Vault — Test Runbook
# Run these commands in order. Each step has a verify check before moving on.
# If any verify fails, stop and fix before continuing.

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0 — Find OpenClaw's config path
# ─────────────────────────────────────────────────────────────────────────────

# Run your find script, then confirm the path
find / -name "openclaw.json" 2>/dev/null
# Note the result — substitute it wherever you see ~/.openclaw below if different

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Install vault dependencies
# ─────────────────────────────────────────────────────────────────────────────

cd /opt/openclaw/keyvault        # or wherever you placed the keyvault files
pip install -r requirements.txt

# VERIFY
python -c "import flask, cryptography, pyotp, jwt, argon2; print('OK')"


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Run vault setup (first-time only)
# ─────────────────────────────────────────────────────────────────────────────

python setup.py

# This will:
#   - Detect your environment (VPS/local/Tailscale/Codespace)
#   - Generate VAULT_MASTER_KEY + JWT_SECRET → /etc/openclaw/vault.env
#   - Set admin password (Argon2 hashed)
#   - Set break-glass recovery passphrase
#   - Optionally set up TOTP (recommended for VPS)
#   - Walk through API key collection (optional at this stage)

# VERIFY
ls -la /etc/openclaw/
# Should see: vault.env (600), vault.meta.json (600), backups/recovery.enc


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Start the vault server
# ─────────────────────────────────────────────────────────────────────────────

# Option A: systemd (production)
cp openclaw-vault.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now openclaw-vault
systemctl status openclaw-vault

# Option B: manual (testing)
source /etc/openclaw/vault.env
gunicorn -w 2 -b 127.0.0.1:7777 vault_server:app &

# VERIFY
curl http://127.0.0.1:7777/health
# Expected: {"status":"ok","env":"vps","vault_exists":true,...}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Open vault admin UI and load your API keys
# ─────────────────────────────────────────────────────────────────────────────

# If on VPS with Caddy: https://vault.yourdomain.com
# If testing locally via SSH tunnel:
ssh -L 7777:127.0.0.1:7777 user@your-vps
# Then open: http://localhost:7777

# Log in with the admin password you set in Step 2
# Go to Keys → Add Key for each provider key:
#   ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, KIMI_API_KEY,
#   ELEVENLABS_API_KEY, TELEGRAM_BOT_TOKEN, TWILIO_ACCOUNT_SID,
#   TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER, OPENCLAW_GATEWAY_TOKEN,
#   NGROK_GATEWAY_URL, RETELL_API_KEY

# VERIFY — list keys via API
curl http://127.0.0.1:7777/health
# Check key count makes sense in the UI


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Mint a machine token for OpenClaw
# ─────────────────────────────────────────────────────────────────────────────

# In the vault UI: Machine Tokens → Mint Token
#   Label:       openclaw-agent
#   Scope:       *
#   Allowed IPs: 127.0.0.1

# COPY THE TOKEN — shown once only

# Test it immediately:
export VAULT_MACHINE_TOKEN=<paste-token-here>
curl -H "Authorization: Bearer $VAULT_MACHINE_TOKEN" http://127.0.0.1:7777/api/keys
# Expected: {"keys":["ANTHROPIC_API_KEY","OPENAI_API_KEY",...]}

# Test fetching a specific key:
curl -H "Authorization: Bearer $VAULT_MACHINE_TOKEN" http://127.0.0.1:7777/api/keys/ANTHROPIC_API_KEY
# Expected: {"name":"ANTHROPIC_API_KEY","value":"sk-ant-..."}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Run the migration (dry-run first)
# ─────────────────────────────────────────────────────────────────────────────

# Point at your actual openclaw.json
export OPENCLAW_CONFIG_PATH=~/.openclaw/openclaw.json   # adjust if different

python migrate_to_vault.py --dry-run
# Should show every secret it found and what vault key it maps to
# Read the output carefully — confirm all secrets are accounted for

# If dry-run looks good, run for real:
python migrate_to_vault.py
# Enter vault admin password when prompted
# This: uploads secrets to vault, rewrites openclaw.json with __VAULT:KEY__ refs
# A backup is written alongside: openclaw.json.pre_vault_<timestamp>.json

# VERIFY
cat ~/.openclaw/openclaw.json | grep -c "__VAULT:"
# Should match the number of secrets migrated (typically 10-15)

cat ~/.openclaw/openclaw.json | grep -v "__VAULT:" | grep -E '"sk-|"AI|"bot[0-9]'
# Should print NOTHING — no raw secrets remaining in the file


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Test the boot injector (dry-run)
# ─────────────────────────────────────────────────────────────────────────────

python openclaw_boot_inject.py --check
# Expected: "Vault connected" + key list

python openclaw_boot_inject.py --dry-run
# Shows every key that would be resolved — confirm all expected keys appear


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Write runtime config (without starting OpenClaw)
# ─────────────────────────────────────────────────────────────────────────────

python openclaw_boot_inject.py --write
# Writes ~/.openclaw/openclaw.runtime.json

# VERIFY the runtime config has real values (not __VAULT: refs)
cat ~/.openclaw/openclaw.runtime.json | grep -c "__VAULT:"
# Expected: 0

# Spot-check a real value is present
cat ~/.openclaw/openclaw.runtime.json | python3 -c "
import json,sys
c = json.load(sys.stdin)
tok = c.get('channels',{}).get('telegram',{}).get('botToken','MISSING')
print('Telegram token present:', tok[:10]+'...' if tok != 'MISSING' else 'MISSING')
"


# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — Test OpenClaw with the runtime config (without systemd)
# ─────────────────────────────────────────────────────────────────────────────

# Stop the current OpenClaw instance first
systemctl stop openclaw    # or however it's currently managed

# Start with injected config manually
OPENCLAW_CONFIG_PATH=~/.openclaw/openclaw.runtime.json openclaw start

# Check it comes up normally — Telegram bot should connect, gateway should start
# Send a test message in Telegram to confirm it's working

# VERIFY
openclaw status   # or check logs
# If OpenClaw starts and Telegram responds → injection is working


# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — Wire up systemd for permanent vault-injected startup
# ─────────────────────────────────────────────────────────────────────────────

# Stop the manual OpenClaw instance
# ctrl+C or kill it

# Edit the agent service with your real paths and token
nano /etc/systemd/system/openclaw-agent.service

# Change these lines:
#   WorkingDirectory=/opt/openclaw   → your actual path
#   ExecStart=...openclaw_boot_inject.py  → full path to the script
#   VAULT_MACHINE_TOKEN=__REPLACE__  → the token from Step 5
#   OPENCLAW_CONFIG_PATH=...         → your actual openclaw.json path

cp openclaw-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now openclaw-agent
systemctl status openclaw-agent

# VERIFY
journalctl -u openclaw-agent -f
# Should see: "Vault connected", "Resolved: ANTHROPIC_API_KEY", etc.
# Then OpenClaw startup logs

# Final check — send a Telegram message to confirm end-to-end


# ─────────────────────────────────────────────────────────────────────────────
# ROLLBACK (if anything goes wrong)
# ─────────────────────────────────────────────────────────────────────────────

# Restore original openclaw.json from backup:
cp ~/.openclaw/openclaw.json.pre_vault_*.json ~/.openclaw/openclaw.json

# Stop vault-injected service, restart old one:
systemctl stop openclaw-agent
systemctl start openclaw   # your original service name

# Everything is back to pre-vault state. Vault server can keep running.
