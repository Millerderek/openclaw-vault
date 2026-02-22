#!/usr/bin/env python3
import os, sys, json, secrets, getpass, socket
from pathlib import Path

missing = []
try:    from cryptography.fernet import Fernet
except: missing.append("cryptography")
try:    from argon2 import PasswordHasher
except: missing.append("argon2-cffi")
try:    import pyotp
except: missing.append("pyotp")
try:    import qrcode
except: missing.append("qrcode[pil]")
if missing:
    print(f"ERROR: Missing packages: {', '.join(missing)}")
    sys.exit(1)

import vault_core as core

CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"
def c(color, text): return f"{color}{text}{RESET}"
def header(text):   print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}\n{BOLD}{CYAN}  {text}{RESET}\n{BOLD}{CYAN}{'─'*60}{RESET}")
def success(text):  print(f"{GREEN}  ✅  {text}{RESET}")
def warn(text):     print(f"{YELLOW}  ⚠️   {text}{RESET}")
def info(text):     print(f"{DIM}  {text}{RESET}")
def ask(prompt):    return input(c(BOLD, f"  {prompt}: ")).strip()

ENV_FILE = Path(os.environ.get("VAULT_ENV", "/etc/openclaw/vault.env"))

CATEGORIES = {
    "AI Model Providers": [
        ("ANTHROPIC_API_KEY",     "Anthropic Claude"),
        ("OPENAI_API_KEY",        "OpenAI GPT-4o / Whisper / Image Gen"),
        ("GOOGLE_API_KEY",        "Google Gemini + nano-banana-pro / goplaces skills"),
        ("KIMI_API_KEY",          "Moonshot Kimi K2.5 — OpenClaw primary"),
        ("OPENROUTER_API_KEY",    "OpenRouter aggregator"),
        ("DEEPSEEK_API_KEY",      "DeepSeek direct"),
        ("GROQ_API_KEY",          "Groq fast inference"),
        ("MISTRAL_API_KEY",       "Mistral AI"),
    ],
    "Voice / TTS / STT": [
        ("ELEVENLABS_API_KEY",    "ElevenLabs TTS — also used by sag skill"),
        ("RETELL_API_KEY",        "Retell.ai WebSocket voice calls"),
    ],
    "Telephony": [
        ("TWILIO_ACCOUNT_SID",    "Twilio Account SID"),
        ("TWILIO_AUTH_TOKEN",     "Twilio Auth Token"),
        ("TWILIO_API_KEY_SID",    "Twilio API Key SID"),
        ("TWILIO_API_KEY_SECRET", "Twilio API Key Secret"),
        ("TWILIO_FROM_NUMBER",    "Twilio outbound phone number"),
    ],
    "Communication": [
        ("TELEGRAM_BOT_TOKEN",    "Telegram bot token"),
        ("SLACK_BOT_TOKEN",       "Slack bot token"),
    ],
    "Productivity & Search": [
        ("BRAVE_SEARCH_API_KEY",  "Brave Search API"),
        ("GOOGLE_SEARCH_API_KEY", "Google Custom Search API key"),
        ("GOOGLE_SEARCH_CX",      "Google Custom Search Engine ID"),
        ("NOTION_API_KEY",        "Notion integration token"),
        ("GITHUB_TOKEN",          "GitHub personal access token"),
    ],
    "Infrastructure": [
        ("NGROK_API_KEY",         "ngrok API key"),
        ("NGROK_GATEWAY_URL",     "ngrok AI Gateway URL"),
        ("TAILSCALE_API_KEY",     "Tailscale API key"),
    ],
    "File & Storage": [
        ("NEXTCLOUD_URL",         "Nextcloud instance URL"),
        ("NEXTCLOUD_USERNAME",    "Nextcloud username"),
        ("NEXTCLOUD_PASSWORD",    "Nextcloud password"),
    ],
    "OpenClaw Internal": [
        ("OPENCLAW_GATEWAY_TOKEN","Gateway auth token (port 18789)"),
    ],
}

def detect_environment():
    if os.environ.get("CODESPACES"):
        return "codespace"
    hostname = socket.getfqdn()
    if hostname.endswith(".internal") or hostname == "localhost":
        return "local"
    return "vps"

def recommended_host(env):
    return "127.0.0.1" if env in ("local", "tailscale") else "0.0.0.0"

def setup_admin_password():
    header("Admin Password")
    info("Protects the web admin UI.")
    while True:
        pw  = getpass.getpass("  Password: ")
        pw2 = getpass.getpass("  Confirm:  ")
        if not pw:
            print(c(YELLOW, "  Cannot be empty.")); continue
        if pw != pw2:
            print(c(YELLOW, "  Passwords don't match.")); continue
        if len(pw) < 12:
            warn("Short password — consider a longer passphrase.")
        ph = PasswordHasher()
        h  = ph.hash(pw)
        success("Admin password set")
        return h

def setup_breakglass():
    header("Break-Glass Recovery Passphrase")
    info("Used to decrypt the vault if the master key is lost.")
    info("Write this down and store it offline.\n")
    while True:
        pw  = getpass.getpass("  Recovery passphrase: ")
        pw2 = getpass.getpass("  Confirm:             ")
        if not pw:
            print(c(YELLOW, "  Cannot be empty.")); continue
        if pw != pw2:
            print(c(YELLOW, "  Don't match.")); continue
        success("Break-glass passphrase set")
        return pw

def load_or_create_crypto_keys():
    master_key = jwt_secret = None
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("VAULT_MASTER_KEY="):
                master_key = line.split("=", 1)[1].strip()
            if line.startswith("JWT_SECRET="):
                jwt_secret = line.split("=", 1)[1].strip()
    if master_key:
        info("Loaded existing master key from vault.env")
    else:
        master_key = Fernet.generate_key().decode()
        success("Generated new VAULT_MASTER_KEY")
    if not jwt_secret:
        jwt_secret = secrets.token_urlsafe(64)
        success("Generated new JWT_SECRET")
    return master_key, jwt_secret

def write_env_file(master_key, jwt_secret, env_name, host):
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    content = (
        f"VAULT_MASTER_KEY={master_key}\n"
        f"JWT_SECRET={jwt_secret}\n"
        f"VAULT_ENV_NAME={env_name}\n"
        f"VAULT_HOST={host}\n"
        f"VAULT_PORT=7777\n"
    )
    ENV_FILE.write_text(content)
    ENV_FILE.chmod(0o600)
    success(f"Env file written: {ENV_FILE}")

def prompt_value(name, current=""):
    masked = ("*" * 6 + current[-4:]) if len(current) > 4 else ("set" if current else "")
    hint   = f" [{masked}]" if current else " [skip=Enter]"
    is_sensitive = any(x in name for x in ("KEY", "TOKEN", "SECRET", "PASSWORD", "SID"))
    try:
        if is_sensitive:
            val = getpass.getpass(f"    Value{hint}: ")
        else:
            val = input(f"    Value{hint}: ").strip()
    except (KeyboardInterrupt, EOFError):
        raise
    if not val and current:
        return current
    return val.strip()

def pick_categories():
    header("Select Key Categories")
    cats = list(CATEGORIES.keys())
    for i, cat in enumerate(cats, 1):
        count = len(CATEGORIES[cat])
        print(f"  {c(CYAN, str(i))}. {cat} ({count} keys)")
    print(f"  {c(CYAN, 'a')}. All categories")
    print(f"  {c(CYAN, 'c')}. Custom keys only")
    print(f"  {c(CYAN, 's')}. Skip key collection")
    choice = ask("Choose (e.g. 1,3,5 or a or s)").lower()
    if choice == "s":
        return [], False
    if choice == "a":
        return cats, True
    if choice == "c":
        return [], True
    selected = []
    add_custom = "c" in choice
    for part in choice.replace(",", " ").split():
        try:
            idx = int(part) - 1
            if 0 <= idx < len(cats):
                selected.append(cats[idx])
        except ValueError:
            pass
    return selected, add_custom

def collect_keys(categories, existing):
    collected = {}
    total = sum(len(CATEGORIES[c]) for c in categories)
    done  = 0
    for cat in categories:
        header(cat)
        for env_name, description in CATEGORIES[cat]:
            done += 1
            current  = existing.get(env_name, "")
            progress = c(DIM, f"[{done}/{total}]")
            print(f"\n  {progress} {c(BOLD, env_name)}")
            print(c(DIM, f"       {description}"))
            try:
                value = prompt_value(env_name, current)
            except (KeyboardInterrupt, EOFError):
                print(f"\n\n{c(YELLOW, '  Interrupted — saving what we have.')}")
                return collected
            if value:
                collected[env_name] = value
                success(f"Stored {env_name}")
            else:
                info(f"Skipped {env_name}")
    return collected

def collect_custom_keys(existing):
    collected = {}
    header("Custom Keys")
    while True:
        try:
            cat_name = input(c(BOLD, "  Category name (or Enter to finish): ")).strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not cat_name:
            break
        while True:
            try:
                env_name = input(c(CYAN, "    Key name: ")).strip().upper()
            except (KeyboardInterrupt, EOFError):
                return collected
            if not env_name:
                break
            current = existing.get(env_name, "")
            try:
                value = prompt_value(env_name, current)
            except (KeyboardInterrupt, EOFError):
                return collected
            if value:
                collected[env_name] = value
                success(f"Stored {env_name}")
    return collected

def main():
    print(f"\n{BOLD}{CYAN}{'='*60}\n   OpenClaw Key Vault — Setup\n{'='*60}{RESET}")

    header("Environment Detection")
    env_name = detect_environment()
    host     = recommended_host(env_name)
    success(f"Detected: {env_name.upper()}")
    if env_name == "vps":
        info("VPS detected. TOTP is strongly recommended.")
    override = ask("Override? [local/vps/tailscale/codespace or Enter to keep]").lower()
    if override in ("local", "vps", "tailscale", "codespace"):
        env_name = override
        host     = recommended_host(env_name)

    header("Encryption Keys")
    master_key, jwt_secret = load_or_create_crypto_keys()
    fernet = Fernet(master_key.encode())

    try:
        existing = core.load_vault(fernet)
        if existing:
            info(f"Found existing vault with {len(existing)} keys.")
    except Exception:
        existing = {}
        warn("No existing vault — starting fresh.")

    meta = core.load_meta()
    if not meta.get("admin_password_hash"):
        admin_hash = setup_admin_password()
        meta["admin_password_hash"] = admin_hash
        core.save_meta(meta)
    else:
        info("Admin password already set.")
        if ask("Change it? [y/N]").lower() in ("y", "yes"):
            meta["admin_password_hash"] = setup_admin_password()
            core.save_meta(meta)

    if not (core.BACKUP_DIR / "recovery.enc").exists():
        core.set_breakglass(setup_breakglass(), fernet)
    else:
        info("Recovery backup exists.")
        if ask("Rotate break-glass passphrase? [y/N]").lower() in ("y", "yes"):
            core.set_breakglass(setup_breakglass(), fernet)

    if not meta.get("totp_enabled"):
        do_totp = env_name == "vps" or ask("Enable TOTP? [y/N]").lower() in ("y", "yes")
        if do_totp:
            secret, url = core.setup_totp("OpenClaw Vault")
            try:
                import qrcode, io
                qr  = qrcode.make(url)
                buf = io.BytesIO()
                qr.save(buf, format="PNG")
                qr_path = core.VAULT_FILE.parent / "totp_setup.png"
                qr_path.parent.mkdir(parents=True, exist_ok=True)
                qr_path.write_bytes(buf.getvalue())
                success(f"QR code saved: {qr_path}")
            except Exception:
                pass
            print(f"\n  {c(CYAN, 'TOTP Secret: ')}{c(BOLD, secret)}")
            warn("Save this secret before continuing!")
            input(c(BOLD, "  Press Enter once saved..."))
    else:
        info("TOTP already enabled.")

    header("API Key Collection")
    chosen_cats, add_custom = pick_categories()
    new_keys = {}
    if chosen_cats:
        new_keys.update(collect_keys(chosen_cats, existing))
    if add_custom:
        new_keys.update(collect_custom_keys({**existing, **new_keys}))

    merged = {**existing, **new_keys}
    if merged:
        core.save_vault(fernet, merged)
        core.write_backup(fernet)

    write_env_file(master_key, jwt_secret, env_name, host)

    header("Setup Complete")
    success(f"Vault:   {core.VAULT_FILE}")
    success(f"Env:     {ENV_FILE}")
    success(f"Keys:    {len(merged)} stored")
    print(f"\n  {c(BOLD, 'Start vault:')}")
    print(f"  {c(CYAN, 'source /etc/openclaw/vault.env')}")
    print(f"  {c(CYAN, 'cd /root/APIKeys && venv/bin/gunicorn -w 2 -b 127.0.0.1:7777 vault_server:app')}\n")
    warn(f"Back up {ENV_FILE} and your break-glass passphrase somewhere safe.")

if __name__ == "__main__":
    main()
