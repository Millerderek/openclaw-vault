#!/usr/bin/env python3
"""
migrate_to_vault.py — Migrate OpenClaw credentials to the key vault.

Sources scanned:
  1. ~/.openclaw/agents/main/agent/auth-profiles.json  (api_key profiles)
  2. ~/.openclaw/openclaw.json                         (channels, gateway, plugins)

auth-profiles.json is NOT rewritten — OpenClaw manages it directly.
openclaw.json paths are rewritten as __VAULT:KEY__ templates.
"""
import os, sys, json, shutil, getpass, argparse
from pathlib import Path
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

VAULT_URL       = os.environ.get("VAULT_URL", "http://127.0.0.1:7777")
OPENCLAW_CONFIG = Path(os.environ.get("OPENCLAW_CONFIG_PATH",
                       os.path.expanduser("~/.openclaw/openclaw.json")))
AUTH_PROFILES   = Path(os.path.expanduser(
                       "~/.openclaw/agents/main/agent/auth-profiles.json"))

PROVIDER_MAP = {
    "anthropic":  "ANTHROPIC_API_KEY",
    "moonshot":   "KIMI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "openai":     "OPENAI_API_KEY",
    "google":     "GOOGLE_API_KEY",
    "gemini":     "GOOGLE_API_KEY",
    "elevenlabs": "ELEVENLABS_API_KEY",
}

SECRET_PATHS = [
    (["env", "GOOGLE_API_KEY"],        "GOOGLE_API_KEY"),
    (["env", "OPENAI_API_KEY"],        "OPENAI_API_KEY"),
    (["env", "ANTHROPIC_API_KEY"],     "ANTHROPIC_API_KEY"),
    (["env", "KIMI_API_KEY"],          "KIMI_API_KEY"),
    (["env", "ELEVENLABS_API_KEY"],    "ELEVENLABS_API_KEY"),
    (["env", "NGROK_GATEWAY_URL"],     "NGROK_GATEWAY_URL"),
    (["env", "GEMINI_API_KEY"],        "GOOGLE_API_KEY"),
    (["skills", "entries", "nano-banana-pro",    "apiKey"], "GOOGLE_API_KEY"),
    (["skills", "entries", "goplaces",           "apiKey"], "GOOGLE_API_KEY"),
    (["skills", "entries", "sag",                "apiKey"], "ELEVENLABS_API_KEY"),
    (["skills", "entries", "openai-image-gen",   "apiKey"], "OPENAI_API_KEY"),
    (["skills", "entries", "openai-whisper-api", "apiKey"], "OPENAI_API_KEY"),
    (["channels", "telegram", "botToken"],                  "TELEGRAM_BOT_TOKEN"),
    (["gateway", "auth", "token"],                          "OPENCLAW_GATEWAY_TOKEN"),
    (["plugins", "entries", "voice-call", "config", "accountSid"],    "TWILIO_ACCOUNT_SID"),
    (["plugins", "entries", "voice-call", "config", "authToken"],     "TWILIO_AUTH_TOKEN"),
    (["plugins", "entries", "voice-call", "config", "fromNumber"],    "TWILIO_FROM_NUMBER"),
    (["plugins", "entries", "voice-call", "config", "tts", "apiKey"], "ELEVENLABS_API_KEY"),
]

CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"
RED="\033[91m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"


def get_nested(obj, path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def set_nested(obj, path, value):
    for key in path[:-1]:
        obj = obj.setdefault(key, {})
    obj[path[-1]] = value


def vault_upload(session, key, value, csrf, dry_run):
    if dry_run:
        print(f"  {DIM}[dry-run] Would upload: {key}{RESET}")
        return True
    try:
        r = session.post(f"{VAULT_URL}/admin/keys/{key}",
                         json={"value": value},
                         headers={"X-CSRF-Token": csrf},
                         timeout=10)
        return r.ok
    except Exception as e:
        print(f"  {RED}Upload failed {key}: {e}{RESET}")
        return False


def login_to_vault(dry_run):
    if dry_run:
        return requests.Session(), "dry-run-csrf"
    print(f"\n{BOLD}Vault Admin Login{RESET} ({VAULT_URL})")
    password = getpass.getpass("  Admin password: ")
    session  = requests.Session()
    r = session.post(f"{VAULT_URL}/admin/login",
                     json={"password": password, "totp": ""},
                     timeout=10)
    data = r.json()
    if data.get("totp_required"):
        totp = input("  TOTP code: ").strip()
        r = session.post(f"{VAULT_URL}/admin/login",
                         json={"password": password, "totp": totp},
                         timeout=10)
    if not r.ok:
        sys.exit(f"{RED}Login failed: {r.json().get('error', 'unknown')}{RESET}")
    csrf = session.cookies.get("csrf_token", "")
    if not csrf:
        sys.exit(f"{RED}No CSRF token received{RESET}")
    print(f"  {GREEN}✓ Authenticated{RESET}")
    return session, csrf


def scan_auth_profiles():
    found = []
    if not AUTH_PROFILES.exists():
        return found
    try:
        data = json.loads(AUTH_PROFILES.read_text())
    except Exception as e:
        print(f"  {YELLOW}Warning: Could not read auth-profiles.json: {e}{RESET}")
        return found
    for profile_name, profile in data.get("profiles", {}).items():
        if profile.get("type") != "api_key":
            continue
        vault_key = PROVIDER_MAP.get(profile.get("provider", ""))
        key_value = profile.get("key", "")
        if vault_key and key_value:
            found.append((vault_key, key_value, f"auth-profiles:{profile_name}"))
    return found


def scan_openclaw_config(config):
    found = []
    for path, vault_key in SECRET_PATHS:
        value = get_nested(config, path)
        if (value
                and isinstance(value, str)
                and not value.startswith("__VAULT:")
                and not value.startswith("__OPENCLAW_REDACTED")):
            found.append((path, vault_key, value))
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Migrate OpenClaw credentials to the key vault")
    parser.add_argument("--dry-run",    action="store_true")
    parser.add_argument("--config",     default=str(OPENCLAW_CONFIG))
    parser.add_argument("--no-rewrite", action="store_true",
                        help="Upload keys but do not rewrite openclaw.json")
    args = parser.parse_args()

    config_path = Path(args.config)
    dry_run     = args.dry_run

    print(f"\n{BOLD}{CYAN}OpenClaw → Vault Migration{RESET}")
    if dry_run:
        print(f"{YELLOW}DRY RUN — no changes will be made{RESET}")

    print(f"\n{BOLD}Scanning auth-profiles.json...{RESET}")
    print(f"  {DIM}{AUTH_PROFILES}{RESET}")
    profile_secrets = scan_auth_profiles()
    for vault_key, _, source in profile_secrets:
        print(f"  {GREEN}✓{RESET} Found: {CYAN}{vault_key}{RESET}  {DIM}({source}){RESET}")
    if not profile_secrets:
        print(f"  {DIM}(none found){RESET}")

    print(f"\n{BOLD}Scanning openclaw.json...{RESET}")
    print(f"  {DIM}{config_path}{RESET}")
    config, config_secrets = {}, []
    if config_path.exists():
        config = json.loads(config_path.read_text())
        config_secrets = scan_openclaw_config(config)
        for _, vault_key, _ in config_secrets:
            print(f"  {GREEN}✓{RESET} Found: {CYAN}{vault_key}{RESET}")
        if not config_secrets:
            print(f"  {DIM}(none found){RESET}")
    else:
        print(f"  {YELLOW}Not found: {config_path}{RESET}")

    total = len(profile_secrets) + len(config_secrets)
    if total == 0:
        print(f"\n{YELLOW}No unvaulted secrets found. Already migrated?{RESET}")
        sys.exit(0)

    print(f"\n{BOLD}{total} secret(s) to migrate.{RESET}")
    session, csrf = login_to_vault(dry_run)

    if not dry_run and config_secrets and not args.no_rewrite:
        ts     = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = config_path.with_suffix(f".pre_vault_{ts}.json")
        shutil.copy2(config_path, backup)
        print(f"\n{GREEN}✓ Backup: {backup}{RESET}")

    print(f"\n{BOLD}Uploading to vault...{RESET}")
    uploaded = set()

    for vault_key, value, source in profile_secrets:
        if vault_key not in uploaded:
            ok = vault_upload(session, vault_key, value, csrf, dry_run)
            if ok:
                print(f"  {GREEN}✓ Uploaded: {vault_key}{RESET}  {DIM}({source}){RESET}")
                uploaded.add(vault_key)
            else:
                print(f"  {RED}✗ Failed:   {vault_key}{RESET}")

    for path, vault_key, value in config_secrets:
        if vault_key not in uploaded:
            ok = vault_upload(session, vault_key, value, csrf, dry_run)
            if ok:
                print(f"  {GREEN}✓ Uploaded: {vault_key}{RESET}")
                uploaded.add(vault_key)
            else:
                print(f"  {RED}✗ Failed:   {vault_key}{RESET}")
                continue
        if not dry_run and not args.no_rewrite:
            set_nested(config, path, f"__VAULT:{vault_key}__")

    if not dry_run and config_secrets and not args.no_rewrite:
        config.pop("_vault_injection", None)
        config_path.write_text(json.dumps(config, indent=2))
        config_path.chmod(0o600)
        print(f"\n{GREEN}✓ openclaw.json rewritten as vault template{RESET}")
        print(f"  {DIM}(auth-profiles.json left intact){RESET}")

    print(f"\n{BOLD}{CYAN}{'─'*50}{RESET}")
    print(f"Secrets found: {total}  |  Uploaded: {len(uploaded)}")
    if not dry_run:
        print(f"\n{BOLD}Next steps:{RESET}")
        print(f"  1. python openclaw_boot_inject.py --check")
        print(f"  2. python openclaw_boot_inject.py --dry-run")
        print(f"  3. python openclaw_boot_inject.py --write")

if __name__ == "__main__":
    main()
