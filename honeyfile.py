import os
import sys
import json
import hashlib
import subprocess
import platform
import socket
import uuid
import psutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import shutil
import secrets
import pwd
import time
import base64
import hashlib

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

# Add fingerprint database
FINGERPRINT_DB = STATE_DIR / "fingerprints.json"
FINGERPRINT_DB.touch(exist_ok=True)

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


# ============================
# FINGERPRINTING FUNCTIONS
# ============================

def get_system_fingerprint() -> dict:
    """Generate a unique fingerprint for the current system"""
    fingerprint = {
        "generated_at": now_iso(),
        "system": {},
        "network": {},
        "users": {},
        "processes": {},
        "filesystem": {},
        "honeyfile": {}
    }
    
    try:
        # System information
        uname = platform.uname()
        fingerprint["system"] = {
            "node": uname.node,
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor,
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "boot_time": psutil.boot_time(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
        }
        
        # Network information
        fingerprint["network"] = {
            "mac_addresses": [],
            "ip_addresses": [],
            "interfaces": []
        }
        
        for iface, addrs in psutil.net_if_addrs().items():
            interface_info = {"name": iface, "addresses": []}
            for addr in addrs:
                addr_info = {
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask if hasattr(addr, 'netmask') else None,
                    "broadcast": addr.broadcast if hasattr(addr, 'broadcast') else None,
                }
                if addr.family == psutil.AF_LINK and addr.address:
                    fingerprint["network"]["mac_addresses"].append(addr.address)
                if addr.family in (socket.AF_INET, socket.AF_INET6) and addr.address:
                    fingerprint["network"]["ip_addresses"].append(addr.address)
                interface_info["addresses"].append(addr_info)
            fingerprint["network"]["interfaces"].append(interface_info)
        
        # User information
        fingerprint["users"] = {
            "current_uid": os.getuid(),
            "current_euid": os.geteuid(),
            "sudo_user": os.environ.get("SUDO_USER"),
            "user": os.environ.get("USER"),
            "login": os.environ.get("LOGNAME"),
            "home": str(Path.home()),
            "shell": os.environ.get("SHELL", ""),
        }
        
        # Active processes (limited to top 50 by memory)
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
            try:
                proc_info = proc.info
                # Only include processes that have cmdline (not kernel threads)
                if proc_info['cmdline']:
                    processes.append(proc_info)
                    if len(processes) >= 50:  # Limit to prevent huge output
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        fingerprint["processes"]["sample"] = processes
        
        # Filesystem fingerprints
        fingerprint["filesystem"] = {
            "mounts": [],
            "partitions": []
        }
        
        for part in psutil.disk_partitions():
            fingerprint["filesystem"]["mounts"].append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "opts": part.opts
            })
        
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                fingerprint["filesystem"]["partitions"].append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                })
            except PermissionError:
                continue
        
        # Honeyfile-specific state
        if MANIFEST_PATH.exists():
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            fingerprint["honeyfile"] = {
                "decoy_dir": manifest.get("decoy_dir"),
                "mode": manifest.get("mode"),
                "files_count": len(manifest.get("files", [])),
                "created_at": manifest.get("created_at"),
                "manifest_hash": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
            }
        
        # Generate a unique ID for this fingerprint
        fingerprint_str = json.dumps(fingerprint, sort_keys=True).encode()
        fingerprint["fingerprint_id"] = hashlib.sha256(fingerprint_str).hexdigest()[:16]
        
    except Exception as e:
        fingerprint["error"] = str(e)
    
    return fingerprint


def get_intrusion_fingerprint(event: dict) -> dict:
    """Generate fingerprint for a specific intrusion event"""
    intrusion_fp = {
        "event_time": event.get("time") or now_iso(),
        "trigger": {},
        "context": {},
        "forensic_artifacts": []
    }
    
    # Trigger information
    intrusion_fp["trigger"] = {
        "file": event.get("file"),
        "syscall": event.get("syscall"),
        "pid": event.get("pid"),
        "exe": event.get("exe"),
        "comm": event.get("comm"),
        "uid": event.get("uid"),
        "auid": event.get("auid"),
        "audit_key": AUDIT_KEY
    }
    
    # Context information
    intrusion_fp["context"] = {
        "system_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": time.time() - psutil.boot_time() if hasattr(psutil, 'boot_time') else None,
        "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else None,
    }
    
    # Try to get more information about the triggering process
    pid = event.get("pid")
    if pid:
        try:
            proc = psutil.Process(int(pid))
            proc_info = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if proc.exe() else None,
                "cmdline": proc.cmdline(),
                "create_time": proc.create_time(),
                "username": proc.username(),
                "status": proc.status(),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_info": dict(proc.memory_info()._asdict()) if hasattr(proc, 'memory_info') else None,
                "connections": []
            }
            
            # Get network connections
            try:
                for conn in proc.connections(kind='inet'):
                    conn_info = {
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status
                    }
                    proc_info["connections"].append(conn_info)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            intrusion_fp["trigger"]["process_details"] = proc_info
            
            # Get open files
            try:
                open_files = []
                for f in proc.open_files():
                    open_files.append({
                        "path": f.path,
                        "fd": f.fd if hasattr(f, 'fd') else None
                    })
                if open_files:
                    intrusion_fp["forensic_artifacts"].append({
                        "type": "open_files",
                        "process_pid": pid,
                        "files": open_files
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            pass
    
    # Check for suspicious patterns
    patterns = check_suspicious_patterns(event)
    if patterns:
        intrusion_fp["suspicious_patterns"] = patterns
    
    # Generate unique ID for this intrusion
    fp_str = json.dumps(intrusion_fp, sort_keys=True).encode()
    intrusion_fp["intrusion_id"] = hashlib.sha256(fp_str).hexdigest()[:16]
    
    return intrusion_fp


def check_suspicious_patterns(event: dict) -> list:
    """Check for known attack patterns in the event"""
    patterns = []
    
    file_path = event.get("file", "").lower()
    exe_path = event.get("exe", "").lower()
    comm = event.get("comm", "").lower()
    
    # Suspicious binary locations
    suspicious_paths = [
        "/tmp/", "/dev/shm/", "/var/tmp/", "/tmp/.",
        "/home/*/.cache/", "/var/run/", "/proc/self/"
    ]
    
    for path in suspicious_paths:
        if path.rstrip('*') in file_path or path.rstrip('*') in exe_path:
            patterns.append(f"executable_in_suspicious_location:{path}")
    
    # Known attack tools
    attack_tools = [
        "nmap", "hydra", "metasploit", "john", "hashcat",
        "sqlmap", "nikto", "wireshark", "tcpdump", "netcat",
        "nc ", "curl", "wget", "scp", "sftp", "rsync",
        "python", "perl", "bash", "sh", "zsh", "ksh"
    ]
    
    for tool in attack_tools:
        if tool in comm or tool in exe_path:
            patterns.append(f"known_tool:{tool}")
    
    # Suspicious system calls
    suspicious_syscalls = ["execve", "ptrace", "connect", "accept", "bind"]
    if event.get("syscall") in suspicious_syscalls:
        patterns.append(f"suspicious_syscall:{event['syscall']}")
    
    # Rapid succession access (would need temporal analysis)
    # This is a placeholder for more complex pattern detection
    
    return patterns


def save_fingerprint(fingerprint: dict, fp_type: str = "system"):
    """Save fingerprint to database"""
    try:
        if FINGERPRINT_DB.stat().st_size > 0:
            db = json.loads(FINGERPRINT_DB.read_text(encoding="utf-8"))
        else:
            db = {"system_fingerprints": [], "intrusion_fingerprints": []}
        
        if fp_type == "system":
            db["system_fingerprints"].append(fingerprint)
            # Keep only last 10 system fingerprints
            if len(db["system_fingerprints"]) > 10:
                db["system_fingerprints"] = db["system_fingerprints"][-10:]
        elif fp_type == "intrusion":
            db["intrusion_fingerprints"].append(fingerprint)
        
        FINGERPRINT_DB.write_text(json.dumps(db, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        print(f"[!] Failed to save fingerprint: {e}")


def compare_fingerprints(old_fp: dict, new_fp: dict) -> dict:
    """Compare two fingerprints and highlight differences"""
    differences = {
        "timestamp": now_iso(),
        "changes": [],
        "anomalies": []
    }
    
    # Compare system information
    for key in ["node", "release", "version"]:
        if old_fp.get("system", {}).get(key) != new_fp.get("system", {}).get(key):
            differences["changes"].append(f"system.{key}: {old_fp.get('system',{}).get(key)} -> {new_fp.get('system',{}).get(key)}")
    
    # Compare network interfaces
    old_ifaces = {iface["name"]: iface for iface in old_fp.get("network", {}).get("interfaces", [])}
    new_ifaces = {iface["name"]: iface for iface in new_fp.get("network", {}).get("interfaces", [])}
    
    for iface_name in set(old_ifaces.keys()) | set(new_ifaces.keys()):
        if iface_name not in new_ifaces:
            differences["changes"].append(f"network.interface.removed: {iface_name}")
        elif iface_name not in old_ifaces:
            differences["changes"].append(f"network.interface.added: {iface_name}")
    
    # Compare IP addresses
    old_ips = set(old_fp.get("network", {}).get("ip_addresses", []))
    new_ips = set(new_fp.get("network", {}).get("ip_addresses", []))
    
    added_ips = new_ips - old_ips
    removed_ips = old_ips - new_ips
    
    if added_ips:
        differences["changes"].append(f"network.ip.added: {list(added_ips)}")
    if removed_ips:
        differences["changes"].append(f"network.ip.removed: {list(removed_ips)}")
    
    return differences


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
    
    # Create initial system fingerprint
    system_fp = get_system_fingerprint()
    save_fingerprint(system_fp, "system")
    
    print(f"[+] Decoy directory created: {decoy_path}")
    print(f"[+] Manifest written: {MANIFEST_PATH}")
    print(f"[+] System fingerprint saved: {system_fp['fingerprint_id']}")
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
    
    # Generate intrusion fingerprints for each event
    intrusion_fingerprints = []
    for event in events:
        intrusion_fp = get_intrusion_fingerprint(event)
        intrusion_fingerprints.append(intrusion_fp)
        save_fingerprint(intrusion_fp, "intrusion")

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
        "intrusion_fingerprints": intrusion_fingerprints,
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

    # Include fingerprint database
    if FINGERPRINT_DB.exists():
        dst_fp = bundle_dir / "fingerprints.json"
        shutil.copy2(FINGERPRINT_DB, dst_fp)
        copied.append(dst_fp)

    # Take current system snapshot
    system_fp = get_system_fingerprint()
    system_fp_path = bundle_dir / "system_snapshot.json"
    system_fp_path.write_text(json.dumps(system_fp, indent=2, default=str), encoding="utf-8")
    copied.append(system_fp_path)

    hashes = []
    for f in copied:
        hashes.append({"file": str(f), "sha256": sha256_file(f)})

    hashes_path = bundle_dir / "SHA256SUMS.json"
    hashes_path.write_text(json.dumps(hashes, indent=2), encoding="utf-8")

    print(f"[+] Evidence bundle created: {bundle_dir}")
    print(f"[+] Hash list: {hashes_path}")
    print(f"[+] System fingerprint: {system_fp['fingerprint_id']}")
    print("[i] Tip: copy the whole bundle to external storage (USB) ASAP.")


def status():
    info = {
        "manifest_exists": MANIFEST_PATH.exists(),
        "auditd_active": auditd_is_running(),
        "owner_user_runtime": OWNER_USER,
        "owner_home_runtime": str(OWNER_HOME),
        "state_dir": str(STATE_DIR),
        "fingerprint_db_exists": FINGERPRINT_DB.exists(),
    }
    
    if FINGERPRINT_DB.exists() and FINGERPRINT_DB.stat().st_size > 0:
        db = json.loads(FINGERPRINT_DB.read_text(encoding="utf-8"))
        info["system_fingerprints_count"] = len(db.get("system_fingerprints", []))
        info["intrusion_fingerprints_count"] = len(db.get("intrusion_fingerprints", []))
        if db.get("system_fingerprints"):
            info["latest_system_fingerprint"] = db["system_fingerprints"][-1].get("fingerprint_id")
    
    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        info["decoy_dir"] = manifest.get("decoy_dir")
        info["mode"] = manifest.get("mode")
        info["files"] = manifest.get("files", [])
    
    print(json.dumps(info, indent=2))


def fingerprint_command():
    """New command to show fingerprint information"""
    if not FINGERPRINT_DB.exists() or FINGERPRINT_DB.stat().st_size == 0:
        print("No fingerprint data available. Run 'init' first.")
        return
    
    db = json.loads(FINGERPRINT_DB.read_text(encoding="utf-8"))
    
    if len(sys.argv) > 2:
        subcmd = sys.argv[2].lower()
        if subcmd == "system":
            print(json.dumps(db.get("system_fingerprints", []), indent=2))
        elif subcmd == "intrusions":
            print(json.dumps(db.get("intrusion_fingerprints", []), indent=2))
        elif subcmd == "compare":
            if len(db.get("system_fingerprints", [])) >= 2:
                old = db["system_fingerprints"][-2]
                new = db["system_fingerprints"][-1]
                diff = compare_fingerprints(old, new)
                print(json.dumps(diff, indent=2))
            else:
                print("Need at least 2 system fingerprints for comparison")
        elif subcmd == "snapshot":
            current = get_system_fingerprint()
            print(json.dumps(current, indent=2))
            save_fingerprint(current, "system")
    else:
        # Show summary
        summary = {
            "system_fingerprints": len(db.get("system_fingerprints", [])),
            "intrusion_fingerprints": len(db.get("intrusion_fingerprints", [])),
            "latest_system_fp": db["system_fingerprints"][-1].get("fingerprint_id") if db.get("system_fingerprints") else None,
            "latest_intrusion_fp": db["intrusion_fingerprints"][-1].get("intrusion_id") if db.get("intrusion_fingerprints") else None,
        }
        print(json.dumps(summary, indent=2))


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
        "  sudo python3 honeyfile.py rotate\n"
        "  python3 honeyfile.py fingerprint [system|intrusions|compare|snapshot]\n\n"
        "Examples:\n"
        "  python3 honeyfile.py init random\n"
        "  sudo python3 honeyfile.py arm\n"
        "  sudo python3 honeyfile.py report 60\n"
        "  sudo python3 honeyfile.py export 60\n"
        "  sudo python3 honeyfile.py rotate\n"
        "  python3 honeyfile.py fingerprint system\n"
        "  python3 honeyfile.py fingerprint compare\n"
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
            
        elif cmd == "fingerprint":
            fingerprint_command()

        else:
            usage()
            sys.exit(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
