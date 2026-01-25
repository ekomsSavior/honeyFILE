import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import shutil
import secrets
import pwd

APP_NAME = "HONEYFILE"


def run(cmd: list[str], check=True) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nSTDERR: {p.stderr.strip()}")
    return p.stdout


def require_root():
    if os.geteuid() != 0:
        print("This command must be run as root. Try: sudo python3 honeyfile.py <command>")
        sys.exit(1)


def get_owner_user() -> str:
    """
    When running under sudo, SUDO_USER is the original user.
    Otherwise fall back to the current USER.
    """
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or ""


def get_owner_home() -> Path:
    """
    Ensure state is stored under the real user's home even when run with sudo.
    Uses /etc/passwd via pwd to avoid assuming /home/<user>.
    """
    owner = get_owner_user()
    if owner:
        try:
            return Path(pwd.getpwnam(owner).pw_dir).resolve()
        except KeyError:
            pass
    return Path.home().resolve()


OWNER_USER = get_owner_user()
OWNER_HOME = get_owner_home()

# State lives under the OWNER's home (not /root), even when running with sudo
STATE_DIR = OWNER_HOME / ".local" / "share" / "honeyfile"
STATE_DIR.mkdir(parents=True, exist_ok=True)

MANIFEST_PATH = STATE_DIR / "manifest.json"
EVIDENCE_DIR = STATE_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_RULES_D = Path("/etc/audit/rules.d")
AUDIT_RULE_FILE = AUDIT_RULES_D / "honeyfile.rules"
AUDIT_KEY = "honeyfile_tripwire"


# Sneaky-but-believable decoy locations (under user profile).
# We avoid system directories to keep it clean and reduce risk.
CANDIDATE_DECOY_DIRS = [
    "~/.cache/.thumbnails/.sys/.db",
    "~/.cache/.sessions/.local/.db",
    "~/.local/share/.telemetry/.cache",
    "~/.local/share/.config/.sync",
    "~/.config/.pulse/.cache",
    "~/.config/.gtk/.icons/.cache",
    "~/.mozilla/.cache/.profiles/.db",
    "~/Documents/.archive/.sync",
    "~/Downloads/.old/.backup",
    "~/.cache/.python/.pip/.wheels",
]


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_random_decoy_dir() -> Path:
    pick = secrets.choice(CANDIDATE_DECOY_DIRS)
    return Path(pick).expanduser().resolve()


def write_decoy_files(decoy_dir: Path):
    decoy_dir.mkdir(parents=True, exist_ok=True)

    # Court-clean: clearly labeled DECOY inside files.
    wallet_txt = decoy_dir / "Wallet_Recovery_Phrases.txt"
    exchange_txt = decoy_dir / "Exchange_API_Keys_2026.txt"
    vpn_cfg = decoy_dir / "VPN_Backup_Configs_DECOY.txt"

    wallet_txt.write_text(
        "DECOY FILE — NOT REAL SECRETS\n"
        "For defensive monitoring only.\n\n"
        "Wallet A: (fake) seed phrase: alpha beta gamma delta ...\n"
        "Wallet B: (fake) seed phrase: red blue green yellow ...\n"
        "Exchange notes: (fake) withdrawal limits, 2FA info\n",
        encoding="utf-8",
    )

    exchange_txt.write_text(
        "DECOY FILE — NOT REAL API KEYS\n"
        "For defensive monitoring only.\n\n"
        "BINANCE_KEY=fake_key_123\n"
        "BINANCE_SECRET=fake_secret_456\n"
        "COINBASE_KEY=fake_key_abc\n"
        "COINBASE_SECRET=fake_secret_def\n",
        encoding="utf-8",
    )

    vpn_cfg.write_text(
        "DECOY FILE — NOT REAL CONFIGS\n"
        "For defensive monitoring only.\n\n"
        "[client]\n"
        "remote vpn.example.com 1194\n"
        "cert fake.crt\n"
        "key fake.key\n",
        encoding="utf-8",
    )

    return [wallet_txt, exchange_txt, vpn_cfg]


def init(mode: str = "random", decoy_dir: str | None = None):
    if mode not in ("random", "fixed"):
        raise ValueError("mode must be 'random' or 'fixed'")

    if mode == "fixed":
        if not decoy_dir:
            raise ValueError("fixed mode requires a decoy_dir path")
        decoy_path = Path(decoy_dir).expanduser().resolve()
    else:
        decoy_path = pick_random_decoy_dir()

    created_files = write_decoy_files(decoy_path)

    manifest = {
        "app": APP_NAME,
        "created_at": now_iso(),
        "owner_user": OWNER_USER,
        "owner_home": str(OWNER_HOME),
        "mode": mode,
        "decoy_dir": str(decoy_path),
        "files": [],
        "candidates": CANDIDATE_DECOY_DIRS,
    }

    for f in created_files:
        manifest["files"].append(
            {"path": str(f), "sha256": sha256_file(f), "size": f.stat().st_size}
        )

    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[+] Decoy directory created: {decoy_path}")
    print(f"[+] Manifest written: {MANIFEST_PATH}")
    print("[i] Next: arm auditing with: sudo python3 honeyfile.py arm")


def auditd_is_running() -> bool:
    try:
        out = run(["systemctl", "is-active", "auditd"], check=False).strip()
        return out == "active"
    except Exception:
        return False


def arm():
    require_root()
    if not auditd_is_running():
        raise RuntimeError("auditd is not running. Start it: sudo systemctl start auditd")

    if not MANIFEST_PATH.exists():
        raise RuntimeError("No manifest found. Run init first: python3 honeyfile.py init random")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    decoy_dir = manifest["decoy_dir"]

    rule_line = f"-w {decoy_dir} -p warx -k {AUDIT_KEY}\n"
    AUDIT_RULE_FILE.write_text(rule_line, encoding="utf-8")

    run(["augenrules", "--load"])
    print(f"[+] Audit rule installed: {AUDIT_RULE_FILE}")
    print(f"[+] Armed audit watch on: {decoy_dir}")
    print("[i] Verify with: sudo auditctl -l | grep honeyfile")


def parse_ausearch_output(text: str):
    events = []
    chunks = re.split(r"\n\s*\n", text.strip(), flags=re.MULTILINE)
    for chunk in chunks:
        if not chunk.strip():
            continue

        ev = {
            "raw": chunk.strip(),
            "time": None,
            "file": None,
            "exe": None,
            "comm": None,
            "pid": None,
            "uid": None,
            "auid": None,
            "syscall": None,
        }

        m = re.search(r"time->(.+)", chunk)
        if m:
            ev["time"] = m.group(1).strip()

        m = re.search(r'name="([^"]+)"', chunk)
        if m:
            ev["file"] = m.group(1)

        m = re.search(r'exe="([^"]+)"', chunk)
        if m:
            ev["exe"] = m.group(1)

        m = re.search(r'comm="([^"]+)"', chunk)
        if m:
            ev["comm"] = m.group(1)

        m = re.search(r"\bpid=(\d+)\b", chunk)
        if m:
            ev["pid"] = m.group(1)

        m = re.search(r"\buid=([0-9]+)\b", chunk)
        if m:
            ev["uid"] = m.group(1)

        m = re.search(r"\bauid=([0-9]+)\b", chunk)
        if m:
            ev["auid"] = m.group(1)

        m = re.search(r"syscall=(\w+)", chunk)
        if m:
            ev["syscall"] = m.group(1)

        events.append(ev)

    return events


def get_ssh_auth_events(minutes: int):
    auth_log = Path("/var/log/auth.log")
    results = []

    if auth_log.exists():
        lines = auth_log.read_text(errors="ignore").splitlines()
        for line in lines[-8000:]:
            if "sshd" not in line:
                continue

            if "Accepted" in line:
                m = re.search(r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", line)
                if m:
                    method, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
                    results.append(
                        {"type": "accepted", "user": user, "ip": ip, "port": port, "method": method, "line": line}
                    )

            if "Failed password" in line or "Invalid user" in line:
                results.append({"type": "failed", "line": line})

    else:
        out = run(["journalctl", "-u", "ssh", "--since", f"{minutes} minutes ago", "--no-pager"], check=False)
        for line in out.splitlines():
            if "Accepted" in line and "sshd" in line:
                m = re.search(r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", line)
                if m:
                    method, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
                    results.append(
                        {"type": "accepted", "user": user, "ip": ip, "port": port, "method": method, "line": line}
                    )

    return results


def report(minutes: int):
    if not MANIFEST_PATH.exists():
        raise RuntimeError("No manifest found. Run init first.")

    start_str = f"{minutes} minutes ago"
    out = run(["ausearch", "-k", AUDIT_KEY, "-i", "--start", start_str], check=False)
    events = parse_ausearch_output(out) if out.strip() else []
    ssh_events = get_ssh_auth_events(minutes)

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    summary = {
        "generated_at": now_iso(),
        "lookback_minutes": minutes,
        "owner_user": manifest.get("owner_user"),
        "decoy_dir": manifest["decoy_dir"],
        "audit_events_count": len(events),
        "ssh_events_count": len(ssh_events),
        "audit_events": events,
        "ssh_events": ssh_events,
    }

    print(json.dumps(summary, indent=2))


def export_evidence(minutes: int):
    require_root()
    if not MANIFEST_PATH.exists():
        raise RuntimeError("No manifest found. Run init first.")

    ts = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    bundle_dir = EVIDENCE_DIR / f"bundle_{ts}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    copied = []

    for p in [Path("/var/log/audit/audit.log"), Path("/var/log/auth.log")]:
        if p.exists():
            dst = bundle_dir / p.name
            shutil.copy2(p, dst)
            copied.append(dst)

    rep = run(["python3", __file__, "report", str(minutes)], check=False)
    report_path = bundle_dir / "report.json"
    report_path.write_text(rep, encoding="utf-8")
    copied.append(report_path)

    dst_manifest = bundle_dir / "manifest.json"
    shutil.copy2(MANIFEST_PATH, dst_manifest)
    copied.append(dst_manifest)

    hashes = []
    for f in copied:
        hashes.append({"file": str(f), "sha256": sha256_file(f)})

    hashes_path = bundle_dir / "SHA256SUMS.json"
    hashes_path.write_text(json.dumps(hashes, indent=2), encoding="utf-8")

    print(f"[+] Evidence bundle created: {bundle_dir}")
    print(f"[+] Hash list: {hashes_path}")
    print("[i] Tip: copy the whole bundle to external storage (USB) ASAP.")


def status():
    info = {
        "manifest_exists": MANIFEST_PATH.exists(),
        "auditd_active": auditd_is_running(),
        "owner_user_runtime": OWNER_USER,
        "owner_home_runtime": str(OWNER_HOME),
        "state_dir": str(STATE_DIR),
    }
    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        info["decoy_dir"] = manifest.get("decoy_dir")
        info["mode"] = manifest.get("mode")
        info["files"] = manifest.get("files", [])
    print(json.dumps(info, indent=2))


def rotate():
    """
    Rotate to a new random location.
    Disarm the audit rule, then re-init (as the owning user), then re-arm (as root).
    """
    require_root()

    if AUDIT_RULE_FILE.exists():
        AUDIT_RULE_FILE.unlink(missing_ok=True)
        run(["augenrules", "--load"], check=False)

    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        raise RuntimeError("Run rotate with sudo from a user session (sudo sets SUDO_USER).")

    # Create new decoy + manifest as the owning user (proper file ownership)
    init_cmd = ["sudo", "-u", sudo_user, "python3", __file__, "init", "random"]
    run(init_cmd)

    arm()
    print("[+] Rotation complete.")


def usage():
    print(
        "Usage:\n"
        "  python3 honeyfile.py init random\n"
        "  python3 honeyfile.py init fixed <path>\n"
        "  sudo python3 honeyfile.py arm\n"
        "  python3 honeyfile.py status\n"
        "  sudo python3 honeyfile.py report <minutes>\n"
        "  sudo python3 honeyfile.py export <minutes>\n"
        "  sudo python3 honeyfile.py rotate\n\n"
        "Examples:\n"
        "  python3 honeyfile.py init random\n"
        "  sudo python3 honeyfile.py arm\n"
        "  sudo python3 honeyfile.py report 60\n"
        "  sudo python3 honeyfile.py export 60\n"
        "  sudo python3 honeyfile.py rotate\n"
    )


def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    cmd = sys.argv[1].lower()
    try:
        if cmd == "init":
            mode = sys.argv[2].lower() if len(sys.argv) > 2 else "random"
            if mode == "fixed":
                if len(sys.argv) < 4:
                    raise RuntimeError("fixed mode requires a path: init fixed <path>")
                init("fixed", sys.argv[3])
            else:
                init("random")

        elif cmd == "arm":
            arm()

        elif cmd == "status":
            status()

        elif cmd == "report":
            minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            report(minutes)

        elif cmd == "export":
            minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            export_evidence(minutes)

        elif cmd == "rotate":
            rotate()

        else:
            usage()
            sys.exit(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
