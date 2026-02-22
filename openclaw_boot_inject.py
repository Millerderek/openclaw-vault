#!/usr/bin/env python3
"""
openclaw_boot_inject.py — Vault → OpenClaw key injector

Runs BEFORE OpenClaw starts. Pulls live keys from the vault and injects
them into all four locations OpenClaw reads credentials from:

  1. env block          openclaw.json → env.GOOGLE_API_KEY etc.
  2. auth profiles      openclaw.json → auth.profiles.anthropic:default.api_key
  3. skills             openclaw.json → skills.entries.nano-banana-pro.apiKey
  4. plugins            openclaw.json → plugins.entries.voice-call.config.*

Keys are written to a TEMP config copy that OpenClaw reads at boot.
The master openclaw.json on disk NEVER contains real keys — only vault
references like "__VAULT:ANTHROPIC_API_KEY__".

Usage:
  python openclaw_boot_inject.py               # inject + print env exports
  python openclaw_boot_inject.py --start       # inject + exec openclaw start
  python openclaw_boot_inject.py --dry-run     # show what would be injected
  python openclaw_boot_inject.py --check       # verify vault connectivity only

Wrapper script (recommended):
  source <(python openclaw_boot_inject.py)     # exports env vars into shell
  openclaw start
"""

import os
import sys
import json
import copy
import shutil
import hashlib
import argparse
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except ImportError:
    sys.exit("ERROR: requests not installed. Run: pip install requests")

# ── Config ────────────────────────────────────────────────────────────────────

VAULT_URL        = os.environ.get("VAULT_URL",        "http://127.0.0.1:7777")
MACHINE_TOKEN    = os.environ.get("VAULT_MACHINE_TOKEN", "")
OPENCLAW_CONFIG  = Path(os.environ.get("OPENCLAW_CONFIG_PATH", os.path.expanduser("~/.openclaw/openclaw.json")))
OPENCLAW_RUNTIME = Path(os.environ.get("OPENCLAW_RUNTIME", os.path.expanduser("~/.openclaw/openclaw.runtime.json")))
OPENCLAW_BIN     = os.environ.get("OPENCLAW_BIN", "openclaw")
INJECT_TIMEOUT   = int(os.environ.get("VAULT_INJECT_TIMEOUT", "10"))

# Prefix used to mark vault references in the config template
VAULT_REF_PREFIX = "__VAULT:"
VAULT_REF_SUFFIX = "__"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [inject] %(levelname)s %(message)s")
log = logging.getLogger("vault.inject")


# ═══════════════════════════════════════════════════════════════════════════════
# Vault client
# ═══════════════════════════════════════════════════════════════════════════════

class VaultClient:
    def __init__(self, url: str, token: str):
        if not token:
            raise SystemExit(
                "ERROR: VAULT_MACHINE_TOKEN not set.\n"
                "Mint a machine token in the vault admin UI, then:\n"
                "  export VAULT_MACHINE_TOKEN=<token>"
            )
        self.url     = url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self._cache: dict[str, str] = {}

    def health(self) -> bool:
        try:
            r = requests.get(f"{self.url}/health", timeout=INJECT_TIMEOUT)
            return r.status_code == 200
        except Exception:
            return False

    def get(self, name: str) -> str | None:
        if name in self._cache:
            return self._cache[name]
        try:
            r = requests.get(
                f"{self.url}/api/keys/{name}",
                headers=self.headers,
                timeout=INJECT_TIMEOUT,
            )
            if r.status_code == 404:
                log.warning("Vault key not found: %s", name)
                return None
            r.raise_for_status()
            value = r.json()["value"]
            self._cache[name] = value
            return value
        except requests.RequestException as e:
            log.error("Vault fetch failed for %s: %s", name, e)
            return None

    def list_keys(self) -> list[str]:
        try:
            r = requests.get(f"{self.url}/api/keys", headers=self.headers, timeout=INJECT_TIMEOUT)
            r.raise_for_status()
            return r.json().get("keys", [])
        except Exception:
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# Config walking — find and resolve vault references
# ═══════════════════════════════════════════════════════════════════════════════

def is_vault_ref(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(VAULT_REF_PREFIX)
        and value.endswith(VAULT_REF_SUFFIX)
    )


def extract_key_name(ref: str) -> str:
    return ref[len(VAULT_REF_PREFIX):-len(VAULT_REF_SUFFIX)]


def walk_and_resolve(obj: Any, vault: VaultClient, dry_run: bool = False) -> tuple[Any, int, int]:
    """
    Recursively walk the config object.
    Replace every __VAULT:KEY_NAME__ string with the live value from vault.
    Returns (resolved_obj, resolved_count, missing_count).
    """
    resolved = 0
    missing  = 0

    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            r, rc, mc = walk_and_resolve(v, vault, dry_run)
            result[k] = r
            resolved += rc
            missing  += mc
        return result, resolved, missing

    elif isinstance(obj, list):
        result = []
        for item in obj:
            r, rc, mc = walk_and_resolve(item, vault, dry_run)
            result.append(r)
            resolved += rc
            missing  += mc
        return result, resolved, missing

    elif is_vault_ref(obj):
        key_name = extract_key_name(obj)
        if dry_run:
            log.info("  [dry-run] Would resolve: %s", key_name)
            return obj, 0, 0
        value = vault.get(key_name)
        if value is not None:
            log.info("  ✓ Resolved: %s", key_name)
            return value, 1, 0
        else:
            log.warning("  ✗ Missing:  %s (kept as placeholder)", key_name)
            return obj, 0, 1

    return obj, 0, 0


# ═══════════════════════════════════════════════════════════════════════════════
# Direct key mapping — known OpenClaw config paths → vault key names
#
# This handles the case where openclaw.json doesn't use __VAULT:__ references
# yet — we map known config locations to vault keys automatically.
# ═══════════════════════════════════════════════════════════════════════════════

# Each entry: (json_path_as_list, vault_key_name)
KNOWN_MAPPINGS = [
    # env block
    (["env", "GOOGLE_API_KEY"],          "GOOGLE_API_KEY"),
    (["env", "OPENAI_API_KEY"],          "OPENAI_API_KEY"),
    (["env", "ANTHROPIC_API_KEY"],       "ANTHROPIC_API_KEY"),
    (["env", "KIMI_API_KEY"],            "KIMI_API_KEY"),
    (["env", "GEMINI_API_KEY"],          "GOOGLE_API_KEY"),   # alias

    # auth profiles
    (["auth", "profiles", "anthropic:default", "api_key"], "ANTHROPIC_API_KEY"),
    (["auth", "profiles", "openai:default",    "api_key"], "OPENAI_API_KEY"),
    (["auth", "profiles", "google:default",    "api_key"], "GOOGLE_API_KEY"),
    (["auth", "profiles", "kimi:default",      "api_key"], "KIMI_API_KEY"),

    # skills
    (["skills", "entries", "nano-banana-pro",  "apiKey"], "GOOGLE_API_KEY"),
    (["skills", "entries", "goplaces",         "apiKey"], "GOOGLE_API_KEY"),
    (["skills", "entries", "sag",              "apiKey"], "ELEVENLABS_API_KEY"),
    (["skills", "entries", "openai-image-gen", "apiKey"], "OPENAI_API_KEY"),
    (["skills", "entries", "openai-whisper-api","apiKey"],"OPENAI_API_KEY"),

    # channels
    (["channels", "telegram", "botToken"],     "TELEGRAM_BOT_TOKEN"),

    # gateway
    (["gateway", "auth", "token"],             "OPENCLAW_GATEWAY_TOKEN"),

    # plugins → voice-call
    (["plugins", "entries", "voice-call", "config", "accountSid"],         "TWILIO_ACCOUNT_SID"),
    (["plugins", "entries", "voice-call", "config", "authToken"],           "TWILIO_AUTH_TOKEN"),
    (["plugins", "entries", "voice-call", "config", "fromNumber"],          "TWILIO_FROM_NUMBER"),
    (["plugins", "entries", "voice-call", "config", "tts", "apiKey"],       "ELEVENLABS_API_KEY"),
]


def set_nested(obj: dict, path: list[str], value: str) -> None:
    """Set a value at a nested dict path, creating intermediate dicts if needed."""
    for key in path[:-1]:
        obj = obj.setdefault(key, {})
    obj[path[-1]] = value


def get_nested(obj: dict, path: list[str]) -> Any:
    """Get a value at a nested dict path. Returns None if path doesn't exist."""
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def apply_known_mappings(config: dict, vault: VaultClient, dry_run: bool = False) -> tuple[int, int]:
    """
    For each known mapping, if the path exists in config (or is missing but
    the vault has the key), inject the value.
    Returns (resolved, missing).
    """
    resolved = 0
    missing  = 0

    for path, vault_key in KNOWN_MAPPINGS:
        # Only inject if the path already exists in config OR if it's an env key
        # (env keys are always safe to add)
        existing = get_nested(config, path)
        is_env   = path[0] == "env"

        if existing is None and not is_env:
            continue   # don't create structure that wasn't there

        if dry_run:
            log.info("  [dry-run] Would inject %s → %s", vault_key, ".".join(path))
            continue

        value = vault.get(vault_key)
        if value:
            set_nested(config, path, value)
            log.info("  ✓ Injected %s → %s", vault_key, ".".join(path))
            resolved += 1
        else:
            if existing and existing != "":
                log.debug("  – Skipped %s (vault missing, kept existing)", vault_key)
            else:
                log.warning("  ✗ Missing  %s (vault key not found)", vault_key)
                missing += 1

    return resolved, missing


# ═══════════════════════════════════════════════════════════════════════════════
# Environment variable export
# ═══════════════════════════════════════════════════════════════════════════════

# These vault keys become process env vars that OpenClaw and its skills can read
ENV_EXPORTS = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "KIMI_API_KEY",
    "OPENROUTER_API_KEY",
    "GROK_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "ELEVENLABS_API_KEY",
    "RETELL_API_KEY",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_API_KEY_SID",
    "TWILIO_API_KEY_SECRET",
    "TWILIO_FROM_NUMBER",
    "TELEGRAM_BOT_TOKEN",
    "SLACK_BOT_TOKEN",
    "BRAVE_SEARCH_API_KEY",
    "GOOGLE_SEARCH_API_KEY",
    "GOOGLE_SEARCH_CX",
    "NOTION_API_KEY",
    "GITHUB_TOKEN",
    "NGROK_API_KEY",
    "NGROK_GATEWAY_URL",
    "NEXTCLOUD_URL",
    "NEXTCLOUD_USERNAME",
    "NEXTCLOUD_PASSWORD",
]


def build_env_exports(vault: VaultClient, dry_run: bool = False) -> dict[str, str]:
    """Fetch all env-exportable keys from vault. Returns {name: value}."""
    available = set(vault.list_keys())
    exports   = {}
    for name in ENV_EXPORTS:
        if name not in available:
            continue
        if dry_run:
            log.info("  [dry-run] Would export: %s", name)
            exports[name] = f"__VAULT:{name}__"
            continue
        value = vault.get(name)
        if value:
            exports[name] = value
            log.info("  ✓ Export: %s", name)
    return exports


# ═══════════════════════════════════════════════════════════════════════════════
# Runtime config writer
# ═══════════════════════════════════════════════════════════════════════════════

def write_runtime_config(config: dict) -> Path:
    """
    Write the injected config to the runtime path (separate from the template).
    The runtime file is chmod 600 and should be .gitignored.
    """
    OPENCLAW_RUNTIME.parent.mkdir(parents=True, exist_ok=True)
    OPENCLAW_RUNTIME.write_text(json.dumps(config, indent=2))
    OPENCLAW_RUNTIME.chmod(0o600)
    log.info("Runtime config written: %s", OPENCLAW_RUNTIME)
    return OPENCLAW_RUNTIME


def stamp_runtime_meta(config: dict) -> dict:
    """No-op: _vault_injection key removed as OpenClaw rejects unknown root keys."""
    return config


# ═══════════════════════════════════════════════════════════════════════════════
# Main injection flow
# ═══════════════════════════════════════════════════════════════════════════════

def run_injection(dry_run: bool = False) -> tuple[dict, dict[str, str]]:
    """
    Full injection pipeline. Returns (runtime_config, env_exports).
    """
    # 1. Connect to vault
    vault = VaultClient(VAULT_URL, MACHINE_TOKEN)
    if not vault.health():
        raise SystemExit(
            f"ERROR: Cannot reach vault at {VAULT_URL}\n"
            f"  Is the vault server running?  systemctl status openclaw-vault\n"
            f"  Is VAULT_URL correct?         export VAULT_URL=http://127.0.0.1:7777"
        )
    log.info("Vault connected: %s", VAULT_URL)

    # 2. Load template config
    if not OPENCLAW_CONFIG.exists():
        raise SystemExit(f"ERROR: OpenClaw config not found: {OPENCLAW_CONFIG}")
    config = json.loads(OPENCLAW_CONFIG.read_text())
    log.info("Config loaded: %s", OPENCLAW_CONFIG)

    # 3. Resolve __VAULT:KEY__ references (explicit template refs)
    log.info("Resolving vault references...")
    config, ref_resolved, ref_missing = walk_and_resolve(config, vault, dry_run)

    # 4. Apply known structural mappings (implicit — no refs needed)
    log.info("Applying known key mappings...")
    map_resolved, map_missing = apply_known_mappings(config, vault, dry_run)

    total_resolved = ref_resolved + map_resolved
    total_missing  = ref_missing  + map_missing

    log.info("Injection complete: %d resolved, %d missing", total_resolved, total_missing)
    if total_missing:
        log.warning("%d vault keys were not found — those config fields unchanged", total_missing)

    # 5. Build env exports
    log.info("Building environment exports...")
    env_exports = build_env_exports(vault, dry_run)

    # 6. Stamp and write runtime config
    if not dry_run:
        config = stamp_runtime_meta(config)
        write_runtime_config(config)

    return config, env_exports


# ═══════════════════════════════════════════════════════════════════════════════
# CLI modes
# ═══════════════════════════════════════════════════════════════════════════════

def mode_check():
    """Just verify vault connectivity and list available keys."""
    vault = VaultClient(VAULT_URL, MACHINE_TOKEN)
    if not vault.health():
        print(f"❌  Vault unreachable at {VAULT_URL}")
        sys.exit(1)
    keys = vault.list_keys()
    print(f"✅  Vault connected: {VAULT_URL}")
    print(f"    {len(keys)} keys available: {', '.join(keys) or '(none)'}")


def mode_dry_run():
    """Show what would be injected without writing anything."""
    print("\n[DRY RUN] — no files written, no vault values fetched\n")
    run_injection(dry_run=True)


def mode_export():
    """
    Print shell export statements to stdout.
    Use with: source <(python openclaw_boot_inject.py)
    """
    _, env_exports = run_injection()
    for name, value in env_exports.items():
        # Shell-escape the value
        escaped = value.replace("'", "'\"'\"'")
        print(f"export {name}='{escaped}'")

    # Also tell OpenClaw to use the runtime config
    print(f"export OPENCLAW_CONFIG_PATH='{OPENCLAW_RUNTIME}'")


def mode_start():
    """Inject keys then exec openclaw start. Keys live only in process env."""
    config, env_exports = run_injection()

    # Build child process environment
    env = os.environ.copy()
    env.update(env_exports)
    env["OPENCLAW_CONFIG_PATH"] = str(OPENCLAW_RUNTIME)

    log.info("Starting OpenClaw with injected credentials...")
    os.execvpe(OPENCLAW_BIN, [OPENCLAW_BIN, "start"], env)   # replaces this process


def mode_write():
    """Write runtime config only (no exec). Useful for debugging."""
    config, env_exports = run_injection()
    print(f"\nRuntime config: {OPENCLAW_RUNTIME}")
    print(f"Env exports:    {len(env_exports)} keys")
    print("\nTo start OpenClaw manually:")
    print(f"  OPENCLAW_CONFIG_PATH={OPENCLAW_RUNTIME} openclaw start")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Inject vault keys into OpenClaw config at boot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check vault connectivity
  python openclaw_boot_inject.py --check

  # See what would be injected (no writes)
  python openclaw_boot_inject.py --dry-run

  # Export env vars into current shell (recommended for manual start)
  source <(python openclaw_boot_inject.py)
  openclaw start

  # Write runtime config + exec openclaw (for systemd)
  python openclaw_boot_inject.py --start

Environment variables:
  VAULT_URL             Vault server URL (default: http://127.0.0.1:7777)
  VAULT_MACHINE_TOKEN   Machine token minted in vault admin UI (required)
  OPENCLAW_CONFIG       Path to openclaw.json template (default: ~/.openclaw/openclaw.json)
  OPENCLAW_RUNTIME      Path to write injected config (default: ~/.openclaw/openclaw.runtime.json)
  OPENCLAW_BIN          OpenClaw binary name/path (default: openclaw)
        """,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check",   action="store_true", help="Verify vault connectivity only")
    group.add_argument("--dry-run", action="store_true", help="Show what would be injected")
    group.add_argument("--start",   action="store_true", help="Inject and exec openclaw start")
    group.add_argument("--write",   action="store_true", help="Write runtime config only")
    args = parser.parse_args()

    if args.check:
        mode_check()
    elif args.dry_run:
        mode_dry_run()
    elif args.start:
        mode_start()
    elif args.write:
        mode_write()
    else:
        mode_export()   # default: print export statements


if __name__ == "__main__":
    main()
