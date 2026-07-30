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
from typing import Optional, List, Dict, Any
import netifaces
import fcntl
import struct

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
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or ""

def get_owner_home() -> Path:
    owner = get_owner_user()
    if owner:
        try:
            return Path(pwd.getpwnam(owner).pw_dir).resolve()
        except KeyError:
            pass
    return Path.home().resolve()

OWNER_USER = get_owner_user()
OWNER_HOME = get_owner_home()

STATE_DIR = OWNER_HOME / ".local" / "share" / "honeyfile"
STATE_DIR.mkdir(parents=True, exist_ok=True)

MANIFEST_PATH = STATE_DIR / "manifest.json"
EVIDENCE_DIR = STATE_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_RULES_D = Path("/etc/audit/rules.d")
AUDIT_RULE_FILE = AUDIT_RULES_D / "honeyfile.rules"
AUDIT_KEY = "honeyfile_tripwire"

FINGERPRINT_DB = STATE_DIR / "fingerprints.json"
FINGERPRINT_DB.touch(exist_ok=True)

IP_TRACKING_DB = STATE_DIR / "ip_tracking.json"
IP_TRACKING_DB.touch(exist_ok=True)

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

# ============================
# IP CAPTURE FUNCTIONS
# ============================

def get_process_network_connections(pid: int) -> List[Dict]:
    """Get all network connections for a process"""
    connections = []
    try:
        proc = psutil.Process(pid)
        for conn in proc.connections(kind='inet'):
            conn_info = {
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "local_ip": conn.laddr.ip if conn.laddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip if conn.raddr else None,
                "remote_port": conn.raddr.port if conn.raddr else None,
            }
            # Only include connections with remote IPs
            if conn_info["remote_ip"] and conn_info["remote_ip"] not in ["127.0.0.1", "::1", "0.0.0.0"]:
                connections.append(conn_info)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return connections

def get_process_tree_network_info(pid: int, max_depth: int = 5) -> Dict[str, Any]:
    """Walk up process tree to find network connections in ancestors"""
    network_info = {
        "pid": pid,
        "process_name": "",
        "remote_ips": [],
        "parent_remote_ips": [],
        "sshd_connection": None,
        "all_connections": []
    }
    
    try:
        current_pid = pid
        depth = 0
        
        while current_pid and depth < max_depth:
            try:
                proc = psutil.Process(current_pid)
                
                # Get process info
                if depth == 0:
                    network_info["process_name"] = proc.name()
                
                # Get connections for this process
                connections = get_process_network_connections(current_pid)
                
                for conn in connections:
                    if conn["remote_ip"]:
                        if depth == 0:
                            network_info["remote_ips"].append({
                                "ip": conn["remote_ip"],
                                "port": conn["remote_port"],
                                "pid": current_pid,
                                "process": proc.name()
                            })
                        else:
                            network_info["parent_remote_ips"].append({
                                "ip": conn["remote_ip"],
                                "port": conn["remote_port"],
                                "pid": current_pid,
                                "process": proc.name(),
                                "depth": depth
                            })
                        
                        # Check if this is sshd
                        if "ssh" in proc.name().lower() or "sshd" in proc.name().lower():
                            network_info["sshd_connection"] = {
                                "pid": current_pid,
                                "remote_ip": conn["remote_ip"],
                                "remote_port": conn["remote_port"],
                                "local_port": conn["local_port"]
                            }
                    
                    network_info["all_connections"].append({
                        "pid": current_pid,
                        "process": proc.name(),
                        "connection": conn
                    })
                
                # Move to parent
                try:
                    parent = proc.parent()
                    current_pid = parent.pid if parent else None
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    current_pid = None
                
                depth += 1
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                break
                
    except Exception as e:
        network_info["error"] = str(e)
    
    return network_info

def get_active_ssh_sessions() -> List[Dict]:
    """Get current SSH sessions with IP addresses"""
    sessions = []
    
    # Method 1: Check sshd processes
    for proc in psutil.process_iter(['pid', 'name', 'connections']):
        try:
            if 'ssh' in proc.info['name'].lower():
                for conn in proc.info['connections'] or []:
                    if conn.raddr and conn.raddr.ip:
                        sessions.append({
                            "pid": proc.info['pid'],
                            "process": proc.info['name'],
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "local_port": conn.laddr.port if conn.laddr else None,
                            "method": "process_scan"
                        })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Method 2: Check logged in users via 'who' or 'last'
    try:
        who_output = run(["who", "-u"], check=False)
        for line in who_output.splitlines():
            parts = line.split()
            if len(parts) >= 7:
                # Format: user pts/0 2024-01-25 14:30 (:0 or IP)
                ip_part = parts[-1]
                if ip_part.startswith('(') and ip_part.endswith(')'):
                    ip = ip_part[1:-1]
                    if ip not in [':0', ':1', 'localhost'] and '.' in ip:
                        sessions.append({
                            "user": parts[0],
                            "tty": parts[1],
                            "remote_ip": ip,
                            "method": "who_command"
                        })
    except Exception:
        pass
    
    return sessions

def get_socket_connections() -> List[Dict]:
    """Get all socket connections using netstat/ss"""
    connections = []
    
    # Try ss first (modern)
    try:
        ss_output = run(["ss", "-tunp"], check=False)
        for line in ss_output.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                state = parts[0]
                local = parts[4]
                remote = parts[5] if len(parts) > 5 else ""
                process = parts[6] if len(parts) > 6 else ""
                
                # Extract IPs
                if remote and remote != "*:*":
                    try:
                        remote_ip = remote.split(':')[0]
                        remote_port = remote.split(':')[1]
                        
                        if remote_ip and remote_ip not in ["0.0.0.0", "127.0.0.1", "::", "::1"]:
                            connections.append({
                                "state": state,
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "local_addr": local,
                                "process": process,
                                "method": "ss"
                            })
                    except IndexError:
                        pass
    except Exception:
        pass
    
    # Fallback to netstat
    try:
        netstat_output = run(["netstat", "-tunp"], check=False)
        for line in netstat_output.splitlines()[2:]:  # Skip headers
            parts = line.split()
            if len(parts) >= 7:
                try:
                    remote_addr = parts[4]
                    if remote_addr and ':' in remote_addr:
                        remote_ip = remote_addr.split(':')[0]
                        if remote_ip and remote_ip not in ["0.0.0.0", "127.0.0.1"]:
                            pid_process = parts[6]
                            pid = pid_process.split('/')[0] if '/' in pid_process else None
                            
                            connections.append({
                                "remote_ip": remote_ip,
                                "remote_port": remote_addr.split(':')[1],
                                "process": pid_process,
                                "pid": pid,
                                "method": "netstat"
                            })
                except IndexError:
                    pass
    except Exception:
        pass
    
    return connections

def get_ip_geolocation(ip: str) -> Dict:
    """Get geolocation info for an IP (without external API calls)"""
    # This is a lightweight method - for full geolocation, you'd need an API
    geo_info = {
        "ip": ip,
        "is_private": False,
        "is_localhost": False,
        "network_type": "unknown"
    }
    
    try:
        # Check if private IP
        if ip.startswith('10.') or ip.startswith('192.168.') or \
           (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
            geo_info["is_private"] = True
            geo_info["network_type"] = "private"
        
        elif ip == "127.0.0.1" or ip == "::1":
            geo_info["is_localhost"] = True
            geo_info["network_type"] = "localhost"
        
        # Simple reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            geo_info["reverse_dns"] = hostname
            
            # Try to extract domain hints
            if hostname.endswith('.com'):
                geo_info["likely_commercial"] = True
            elif hostname.endswith('.edu'):
                geo_info["likely_education"] = True
            elif hostname.endswith('.gov'):
                geo_info["likely_government"] = True
            elif hostname.endswith('.org'):
                geo_info["likely_organization"] = True
                
        except (socket.herror, socket.gaierror):
            pass
        
    except Exception:
        pass
    
    return geo_info

def save_ip_to_tracking_db(ip_info: Dict):
    """Save IP information to tracking database"""
    try:
        if IP_TRACKING_DB.stat().st_size > 0:
            db = json.loads(IP_TRACKING_DB.read_text(encoding="utf-8"))
        else:
            db = {"ips": [], "first_seen": {}, "last_seen": {}}
        
        ip = ip_info.get("ip")
        if ip:
            # Update tracking
            timestamp = now_iso()
            
            if ip not in db["first_seen"]:
                db["first_seen"][ip] = timestamp
            
            db["last_seen"][ip] = timestamp
            
            # Add to IP list if not already there
            if not any(entry.get("ip") == ip for entry in db["ips"]):
                db["ips"].append(ip_info)
            
            # Keep only last 100 unique IPs
            if len(db["ips"]) > 100:
                db["ips"] = db["ips"][-100:]
            
            IP_TRACKING_DB.write_text(json.dumps(db, indent=2, default=str), encoding="utf-8")
            
    except Exception as e:
        print(f"[!] Failed to save IP to tracking DB: {e}")

# ============================
# ENHANCED INTRUSION FINGERPRINTING WITH IP
# ============================

def get_intrusion_fingerprint_with_ip(event: dict) -> dict:
    """Generate fingerprint for intrusion WITH IP capture"""
    intrusion_fp = {
        "event_time": event.get("time") or now_iso(),
        "trigger": {},
        "network_analysis": {},
        "ip_attribution": {},
        "context": {},
        "forensic_artifacts": []
    }
    
    # Basic trigger info
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
    
    pid = event.get("pid")
    if pid:
        try:
            # Get detailed process info
            proc = psutil.Process(int(pid))
            proc_info = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if proc.exe() else None,
                "cmdline": proc.cmdline(),
                "create_time": proc.create_time(),
                "username": proc.username(),
                "status": proc.status(),
                "cwd": proc.cwd() if hasattr(proc, 'cwd') else None,
                "ppid": proc.ppid(),
                "parent_name": "",
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_info": dict(proc.memory_info()._asdict()) if hasattr(proc, 'memory_info') else None,
            }
            
            # Get parent process info
            try:
                parent = proc.parent()
                if parent:
                    proc_info["parent_name"] = parent.name()
                    proc_info["parent_pid"] = parent.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            intrusion_fp["trigger"]["process_details"] = proc_info
            
            # NETWORK ANALYSIS - KEY IP CAPTURE
            intrusion_fp["network_analysis"] = {
                "process_connections": get_process_network_connections(int(pid)),
                "process_tree_analysis": get_process_tree_network_info(int(pid)),
                "active_ssh_sessions": get_active_ssh_sessions(),
                "all_socket_connections": get_socket_connections(),
                "current_user_sessions": []
            }
            
            # Get user sessions
            try:
                user = proc.username()
                who_output = run(["who"], check=False)
                for line in who_output.splitlines():
                    if user in line:
                        intrusion_fp["network_analysis"]["current_user_sessions"].append(line)
            except Exception:
                pass
            
            # IP ATTRIBUTION - Compile all IP evidence
            all_ips = set()
            
            # From process connections
            for conn in intrusion_fp["network_analysis"]["process_connections"]:
                if conn.get("remote_ip"):
                    all_ips.add(conn["remote_ip"])
            
            # From process tree
            tree_info = intrusion_fp["network_analysis"]["process_tree_analysis"]
            for ip_info in tree_info.get("remote_ips", []):
                if ip_info.get("ip"):
                    all_ips.add(ip_info["ip"])
            
            for ip_info in tree_info.get("parent_remote_ips", []):
                if ip_info.get("ip"):
                    all_ips.add(ip_info["ip"])
            
            # From SSH sessions
            for session in intrusion_fp["network_analysis"]["active_ssh_sessions"]:
                if session.get("remote_ip"):
                    all_ips.add(session["remote_ip"])
            
            # From all sockets
            for conn in intrusion_fp["network_analysis"]["all_socket_connections"]:
                if conn.get("remote_ip"):
                    all_ips.add(conn["remote_ip"])
            
            # Enrich IP information
            intrusion_fp["ip_attribution"] = {
                "all_ips_detected": list(all_ips),
                "ip_details": [],
                "most_likely_source": None
            }
            
            # Get details for each IP
            for ip in all_ips:
                geo_info = get_ip_geolocation(ip)
                intrusion_fp["ip_attribution"]["ip_details"].append(geo_info)
                
                # Save to tracking DB
                save_ip_to_tracking_db({
                    "ip": ip,
                    "first_seen_event": intrusion_fp["event_time"],
                    "source_pid": pid,
                    "process": proc_info["name"],
                    "geolocation": geo_info,
                    "trigger_file": event.get("file")
                })
            
            # Determine most likely source IP
            if all_ips:
                # Prefer SSH connections
                ssh_ips = [s["remote_ip"] for s in intrusion_fp["network_analysis"]["active_ssh_sessions"] 
                          if s.get("remote_ip")]
                if ssh_ips:
                    intrusion_fp["ip_attribution"]["most_likely_source"] = ssh_ips[0]
                else:
                    # Use first non-local IP
                    non_local_ips = [ip for ip in all_ips if not ip.startswith('127.') and ip != '::1']
                    if non_local_ips:
                        intrusion_fp["ip_attribution"]["most_likely_source"] = non_local_ips[0]
            
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
            
            # Get environment variables
            try:
                env = proc.environ()
                if env:
                    intrusion_fp["trigger"]["process_details"]["environment"] = {
                        k: v for k, v in env.items() 
                        if not any(sensitive in k.lower() for sensitive in ['pass', 'secret', 'key', 'token'])
                    }
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as e:
            intrusion_fp["trigger"]["process_error"] = str(e)
    
    # Check for suspicious patterns
    patterns = check_suspicious_patterns(event)
    if patterns:
        intrusion_fp["suspicious_patterns"] = patterns
    
    # Generate unique ID
    fp_str = json.dumps(intrusion_fp, sort_keys=True).encode()
    intrusion_fp["intrusion_id"] = hashlib.sha256(fp_str).hexdigest()[:16]
    
    return intrusion_fp

def check_suspicious_patterns(event: dict) -> list:
    """Check for known attack patterns"""
    patterns = []
    
    file_path = event.get("file", "").lower()
    exe_path = event.get("exe", "").lower()
    comm = event.get("comm", "").lower()
    
    # Suspicious locations
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
    
    return patterns

# ============================
# ENHANCED REPORTING WITH IP
# ============================

def report(minutes: int):
    if not MANIFEST_PATH.exists():
        raise RuntimeError("No manifest found. Run init first.")

    start_str = f"{minutes} minutes ago"
    out = run(["ausearch", "-k", AUDIT_KEY, "-i", "--start", start_str], check=False)
    events = parse_ausearch_output(out) if out.strip() else []
    ssh_events = get_ssh_auth_events(minutes)
    
    # Generate intrusion fingerprints WITH IP CAPTURE
    intrusion_fingerprints = []
    for event in events:
        intrusion_fp = get_intrusion_fingerprint_with_ip(event)
        intrusion_fingerprints.append(intrusion_fp)
        save_fingerprint(intrusion_fp, "intrusion")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    # IP SUMMARY
    all_ips = set()
    for fp in intrusion_fingerprints:
        for ip in fp.get("ip_attribution", {}).get("all_ips_detected", []):
            all_ips.add(ip)
    
    summary = {
        "generated_at": now_iso(),
        "lookback_minutes": minutes,
        "owner_user": manifest.get("owner_user"),
        "decoy_dir": manifest["decoy_dir"],
        "audit_events_count": len(events),
        "ssh_events_count": len(ssh_events),
        "unique_ips_detected": list(all_ips),
        "audit_events": events,
        "ssh_events": ssh_events,
        "intrusion_fingerprints": intrusion_fingerprints,
    }

    print(json.dumps(summary, indent=2))

# ============================
#  IP TRACKING COMMANDS
# ============================

def show_ip_tracking():
    """Show all tracked IPs"""
    if not IP_TRACKING_DB.exists() or IP_TRACKING_DB.stat().st_size == 0:
        print("No IP tracking data available.")
        return
    
    db = json.loads(IP_TRACKING_DB.read_text(encoding="utf-8"))
    
    if len(sys.argv) > 2:
        subcmd = sys.argv[2].lower()
        
        if subcmd == "list":
            print(json.dumps(db.get("ips", []), indent=2))
            
        elif subcmd == "timeline":
            timeline = []
            for ip, first_seen in db.get("first_seen", {}).items():
                last_seen = db.get("last_seen", {}).get(ip, "")
                timeline.append({
                    "ip": ip,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "ip_info": next((info for info in db.get("ips", []) if info.get("ip") == ip), {})
                })
            print(json.dumps(sorted(timeline, key=lambda x: x["first_seen"]), indent=2))
            
        elif subcmd == "summary":
            summary = {
                "total_unique_ips": len(db.get("ips", [])),
                "first_seen_count": len(db.get("first_seen", {})),
                "last_seen_count": len(db.get("last_seen", {})),
                "recent_ips": list(db.get("last_seen", {}).keys())[-10:],
                "private_ips": [ip for ip in db.get("ips", []) if ip.get("geolocation", {}).get("is_private")],
                "public_ips": [ip for ip in db.get("ips", []) if not ip.get("geolocation", {}).get("is_private") and not ip.get("geolocation", {}).get("is_localhost")]
            }
            print(json.dumps(summary, indent=2))
    else:
        # Default summary
        summary = {
            "total_tracked_ips": len(db.get("ips", [])),
            "first_tracked": min(db.get("first_seen", {}).values()) if db.get("first_seen") else None,
            "last_tracked": max(db.get("last_seen", {}).values()) if db.get("last_seen") else None,
            "recent_activity": len([v for v in db.get("last_seen", {}).values() 
                                   if datetime.fromisoformat(v.replace('Z', '+00:00')) > 
                                   datetime.now(timezone.utc) - timedelta(hours=24)])
        }
        print(json.dumps(summary, indent=2))

def export_ip_intelligence():
    """Export IP intelligence for threat intelligence sharing"""
    require_root()
    
    if not IP_TRACKING_DB.exists() or IP_TRACKING_DB.stat().st_size == 0:
        print("No IP tracking data to export.")
        return
    
    db = json.loads(IP_TRACKING_DB.read_text(encoding="utf-8"))
    
    # Format for threat intelligence platforms
    threat_intel = {
        "generated_at": now_iso(),
        "tool": "honeyFILE",
        "version": "1.0",
        "ips": [],
        "indicators": []
    }
    
    for ip_info in db.get("ips", []):
        ip = ip_info.get("ip")
        if ip:
            # Create indicator
            indicator = {
                "type": "ipv4",
                "value": ip,
                "first_seen": db.get("first_seen", {}).get(ip),
                "last_seen": db.get("last_seen", {}).get(ip),
                "confidence": "high",
                "tags": ["honeypot", "intrusion", "unauthorized-access"],
                "source": "honeyFILE_decoy_access"
            }
            
            # Add geolocation if available
            if ip_info.get("geolocation"):
                indicator["geolocation"] = ip_info["geolocation"]
            
            threat_intel["indicators"].append(indicator)
            threat_intel["ips"].append(ip_info)
    
    # Create export file
    ts = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    export_file = EVIDENCE_DIR / f"ip_intelligence_{ts}.json"
    export_file.write_text(json.dumps(threat_intel, indent=2, encoding="utf-8"))
    
    print(f"[+] IP intelligence exported: {export_file}")
    print(f"[+] Indicators: {len(threat_intel['indicators'])}")
    print("[i] Share with: SOC, Threat Intel Platforms, AbuseIPDB")

# ============================
# ORIGINAL FUNCTIONS
# ============================

def pick_random_decoy_dir() -> Path:
    pick = secrets.choice(CANDIDATE_DECOY_DIRS)
    return Path(pick).expanduser().resolve()

def write_decoy_files(decoy_dir: Path):
    decoy_dir.mkdir(parents=True, exist_ok=True)

    wallet_txt = decoy_dir / "Wallet_Recovery_Phrases.txt"
    exchange_txt = decoy_dir / "Exchange_API_Keys_2026.txt"
    vpn_cfg = decoy_dir / "VPN_Backup_Configs_DECOY.txt"

    wallet_txt.write_text(
        "DECOY FILE — NOT REAL SECRETS\nFor defensive monitoring only.\n\n" +
        "Wallet A: (fake) seed phrase: alpha beta gamma delta ...\n" +
        "Wallet B: (fake) seed phrase: red blue green yellow ...\n" +
        "Exchange notes: (fake) withdrawal limits, 2FA info\n",
        encoding="utf-8",
    )

    exchange_txt.write_text(
        "DECOY FILE — NOT REAL API KEYS\nFor defensive monitoring only.\n\n" +
        "BINANCE_KEY=fake_key_123\nBINANCE_SECRET=fake_secret_456\n" +
        "COINBASE_KEY=fake_key_abc\nCOINBASE_SECRET=fake_secret_def\n",
        encoding="utf-8",
    )

    vpn_cfg.write_text(
        "DECOY FILE — NOT REAL CONFIGS\nFor defensive monitoring only.\n\n" +
        "[client]\nremote vpn.example.com 1194\ncert fake.crt\nkey fake.key\n",
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
    
    system_fp = get_system_fingerprint()
    save_fingerprint(system_fp, "system")
    
    print(f"[+] Decoy directory created: {decoy_path}")
    print(f"[+] Manifest written: {MANIFEST_PATH}")
    print(f"[+] System fingerprint saved")
    print("[i] Next: arm auditing with: sudo python3 honeyfile.py arm")

def get_system_fingerprint() -> dict:
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
        
        fingerprint["users"] = {
            "current_uid": os.getuid(),
            "current_euid": os.geteuid(),
            "sudo_user": os.environ.get("SUDO_USER"),
            "user": os.environ.get("USER"),
            "login": os.environ.get("LOGNAME"),
            "home": str(Path.home()),
            "shell": os.environ.get("SHELL", ""),
        }
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
            try:
                proc_info = proc.info
                if proc_info['cmdline']:
                    processes.append(proc_info)
                    if len(processes) >= 50:
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        fingerprint["processes"]["sample"] = processes
        
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
        
        if MANIFEST_PATH.exists():
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            fingerprint["honeyfile"] = {
                "decoy_dir": manifest.get("decoy_dir"),
                "mode": manifest.get("mode"),
                "files_count": len(manifest.get("files", [])),
                "created_at": manifest.get("created_at"),
                "manifest_hash": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
            }
        
        fingerprint_str = json.dumps(fingerprint, sort_keys=True).encode()
        fingerprint["fingerprint_id"] = hashlib.sha256(fingerprint_str).hexdigest()[:16]
        
    except Exception as e:
        fingerprint["error"] = str(e)
    
    return fingerprint

def save_fingerprint(fingerprint: dict, fp_type: str = "system"):
    try:
        if FINGERPRINT_DB.stat().st_size > 0:
            db = json.loads(FINGERPRINT_DB.read_text(encoding="utf-8"))
        else:
            db = {"system_fingerprints": [], "intrusion_fingerprints": []}
        
        if fp_type == "system":
            db["system_fingerprints"].append(fingerprint)
            if len(db["system_fingerprints"]) > 10:
                db["system_fingerprints"] = db["system_fingerprints"][-10:]
        elif fp_type == "intrusion":
            db["intrusion_fingerprints"].append(fingerprint)
        
        FINGERPRINT_DB.write_text(json.dumps(db, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        print(f"[!] Failed to save fingerprint: {e}")

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

    if FINGERPRINT_DB.exists():
        dst_fp = bundle_dir / "fingerprints.json"
        shutil.copy2(FINGERPRINT_DB, dst_fp)
        copied.append(dst_fp)
    
    if IP_TRACKING_DB.exists():
        dst_ip = bundle_dir / "ip_tracking.json"
        shutil.copy2(IP_TRACKING_DB, dst_ip)
        copied.append(dst_ip)

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
    print("[i] Tip: copy the whole bundle to external storage (USB) ASAP.")

def status():
    info = {
        "manifest_exists": MANIFEST_PATH.exists(),
        "auditd_active": auditd_is_running(),
        "owner_user_runtime": OWNER_USER,
        "owner_home_runtime": str(OWNER_HOME),
        "state_dir": str(STATE_DIR),
        "fingerprint_db_exists": FINGERPRINT_DB.exists(),
        "ip_tracking_db_exists": IP_TRACKING_DB.exists(),
    }
    
    if FINGERPRINT_DB.exists() and FINGERPRINT_DB.stat().st_size > 0:
        db = json.loads(FINGERPRINT_DB.read_text(encoding="utf-8"))
        info["system_fingerprints_count"] = len(db.get("system_fingerprints", []))
        info["intrusion_fingerprints_count"] = len(db.get("intrusion_fingerprints", []))
        if db.get("system_fingerprints"):
            info["latest_system_fingerprint"] = db["system_fingerprints"][-1].get("fingerprint_id")
    
    if IP_TRACKING_DB.exists() and IP_TRACKING_DB.stat().st_size > 0:
        db = json.loads(IP_TRACKING_DB.read_text(encoding="utf-8"))
        info["tracked_ips_count"] = len(db.get("ips", []))
        info["unique_ips_seen"] = len(db.get("first_seen", {}))
    
    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        info["decoy_dir"] = manifest.get("decoy_dir")
        info["mode"] = manifest.get("mode")
        info["files"] = manifest.get("files", [])
    
    print(json.dumps(info, indent=2))

def fingerprint_command():
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
        summary = {
            "system_fingerprints": len(db.get("system_fingerprints", [])),
            "intrusion_fingerprints": len(db.get("intrusion_fingerprints", [])),
            "latest_system_fp": db["system_fingerprints"][-1].get("fingerprint_id") if db.get("system_fingerprints") else None,
            "latest_intrusion_fp": db["intrusion_fingerprints"][-1].get("intrusion_id") if db.get("intrusion_fingerprints") else None,
        }
        print(json.dumps(summary, indent=2))

def compare_fingerprints(old_fp: dict, new_fp: dict) -> dict:
    differences = {
        "timestamp": now_iso(),
        "changes": [],
        "anomalies": []
    }
    
    for key in ["node", "release", "version"]:
        if old_fp.get("system", {}).get(key) != new_fp.get("system", {}).get(key):
            differences["changes"].append(f"system.{key}: {old_fp.get('system',{}).get(key)} -> {new_fp.get('system',{}).get(key)}")
    
    old_ifaces = {iface["name"]: iface for iface in old_fp.get("network", {}).get("interfaces", [])}
    new_ifaces = {iface["name"]: iface for iface in new_fp.get("network", {}).get("interfaces", [])}
    
    for iface_name in set(old_ifaces.keys()) | set(new_ifaces.keys()):
        if iface_name not in new_ifaces:
            differences["changes"].append(f"network.interface.removed: {iface_name}")
        elif iface_name not in old_ifaces:
            differences["changes"].append(f"network.interface.added: {iface_name}")
    
    old_ips = set(old_fp.get("network", {}).get("ip_addresses", []))
    new_ips = set(new_fp.get("network", {}).get("ip_addresses", []))
    
    added_ips = new_ips - old_ips
    removed_ips = old_ips - new_ips
    
    if added_ips:
        differences["changes"].append(f"network.ip.added: {list(added_ips)}")
    if removed_ips:
        differences["changes"].append(f"network.ip.removed: {list(removed_ips)}")
    
    return differences

def rotate():
    require_root()

    if AUDIT_RULE_FILE.exists():
        AUDIT_RULE_FILE.unlink(missing_ok=True)
        run(["augenrules", "--load"], check=False)

    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        raise RuntimeError("Run rotate with sudo from a user session (sudo sets SUDO_USER).")

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
        "  python3 honeyfile.py fingerprint [system|intrusions|compare|snapshot]\n"
        "  python3 honeyfile.py iptrack [list|timeline|summary]\n"
        "  sudo python3 honeyfile.py export_ips\n\n"
        "Examples:\n"
        "  python3 honeyfile.py init random\n"
        "  sudo python3 honeyfile.py arm\n"
        "  sudo python3 honeyfile.py report 60\n"
        "  sudo python3 honeyfile.py export 60\n"
        "  sudo python3 honeyfile.py rotate\n"
        "  python3 honeyfile.py fingerprint system\n"
        "  python3 honeyfile.py fingerprint compare\n"
        "  python3 honeyfile.py iptrack timeline\n"
        "  sudo python3 honeyfile.py export_ips\n"
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
            
        elif cmd == "iptrack":
            show_ip_tracking()
            
        elif cmd == "export_ips":
            export_ip_intelligence()

        else:
            usage()
            sys.exit(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
