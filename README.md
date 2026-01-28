# honeyFILE 

**Defensive honeyFILE Tripwire for Linux with Advanced Fingerprinting & IP Attribution**

`honeyFILE` is a **legal, non-harmful defensive deception tool** that plants decoy files ("honeyfiles") in **realistic hidden locations** on your system, uses **kernel-level auditing** to alert you when someone accesses them, and provides **advanced forensic fingerprinting with IP attribution** for incident response.

---

##  What honeyFILE Does

* Creates **decoy files** that look valuable to an intruder
* Places them in **sneaky but believable locations** under the user's home directory
* Uses **auditd** to log all access attempts with full forensic context
* **Captures intruder IP addresses** from network connections and process trees
* Performs **system fingerprinting** to establish baseline system state
* Generates **intrusion fingerprints** with detailed attacker context
* Creates **forensic evidence bundles** with cryptographic integrity
* Supports **randomized rotation** to prevent pattern recognition
* **Tracks IP intelligence** for threat hunting and attribution

---

##  Threat Model

honeyFILE is designed to detect:

* Unauthorized local file browsing
* Post-compromise attacker curiosity
* SSH intrusions (password or key-based) **with source IP capture**
* Lateral movement reconnaissance
* "Living off the land" attackers poking around user data
* Insider threats accessing sensitive-looking files
* Persistence mechanism discovery
* **Remote attacker attribution** through IP tracking

It is **not** meant to stop the intrusion by itself — it provides **early detection, attribution with IP evidence, and forensic documentation**.

---

##  Dependencies

### System Packages
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd

# Optional: For better network analysis
sudo apt install -y net-tools iproute2
```

### Python Requirements
```bash
pip install psutil --break-system-packages
```
or do a venv if you have a problem with --break-system-packages
---

##  Quick Start

### 1. Clone and Install
```bash
git clone https://github.com/ekomsSavior/honeyFILE.git
cd honeyFILE
```

### 2. Initialize honeyFILE
```bash
# Random hidden location (recommended for production)
python3 honeyfile.py init random

# Fixed location (for testing)
python3 honeyfile.py init fixed ~/.hidden_secrets
```

### 3. Arm the System
```bash
sudo python3 honeyfile.py arm
```

### 4. Verify Installation
```bash
# Check status
python3 honeyfile.py status

# Verify audit rules
sudo auditctl -l | grep honeyfile
```

---

##  Complete Command Reference

###  **Initialization & Setup**
```bash
# Initialize with random hidden location (recommended)
python3 honeyfile.py init random

# Initialize with specific directory
python3 honeyfile.py init fixed /path/to/hidden/dir

# Install auditd rules (requires sudo)
sudo python3 honeyfile.py arm

# Check current status and configuration
python3 honeyfile.py status
```

###  **Monitoring & Detection**
```bash
# Generate report for last N minutes (default: 60)
sudo python3 honeyfile.py report <minutes>

# Example: Check last 2 hours of activity
sudo python3 honeyfile.py report 120

# Example: Check last 24 hours
sudo python3 honeyfile.py report 1440

# Export forensic evidence bundle
sudo python3 honeyfile.py export <minutes>

# Export with comprehensive evidence
sudo python3 honeyfile.py export 1440  # Last 24 hours
```

###  **Fingerprinting & Analysis**
```bash
# Show fingerprint database summary
python3 honeyfile.py fingerprint

# View all system fingerprints
python3 honeyfile.py fingerprint system

# View all intrusion fingerprints with attacker details
python3 honeyfile.py fingerprint intrusions

# Compare system state changes over time
python3 honeyfile.py fingerprint compare

# Take new system snapshot
python3 honeyfile.py fingerprint snapshot
```

###  **IP Tracking & Attribution**
```bash
# Show IP tracking summary
python3 honeyfile.py iptrack

# List all tracked IPs with details
python3 honeyfile.py iptrack list

# Show IP timeline (first/last seen)
python3 honeyfile.py iptrack timeline

# Export IP intelligence for threat sharing (requires sudo)
sudo python3 honeyfile.py export_ips
```

###  **Maintenance & Rotation**
```bash
# Rotate to new random location (requires sudo)
sudo python3 honeyfile.py rotate

# This will:
# 1. Remove old audit rules
# 2. Create new decoy location
# 3. Update manifest
# 4. Install new audit rules
```

---

##  **Command Output Reference**

### **`status` Command Output:**
```json
{
  "manifest_exists": true,
  "auditd_active": true,
  "owner_user_runtime": "user",
  "owner_home_runtime": "/home/user",
  "state_dir": "/home/user/.local/share/honeyfile",
  "fingerprint_db_exists": true,
  "ip_tracking_db_exists": true,
  "system_fingerprints_count": 5,
  "intrusion_fingerprints_count": 2,
  "tracked_ips_count": 3,
  "decoy_dir": "/home/user/.cache/.thumbnails/.sys/.db",
  "mode": "random",
  "files": [
    {"path": "...", "sha256": "...", "size": 1234}
  ]
}
```

### **`report` Command Output Includes:**
- **Audit Events Count**: Number of decoy file accesses
- **SSH Events Count**: SSH authentication attempts
- **Unique IPs Detected**: All captured IP addresses
- **Audit Events**: Detailed access logs with timestamps
- **SSH Events**: Authentication successes/failures
- **Intrusion Fingerprints**: Complete attacker profiles including:
  - **Process details** (PID, command line, parent process)
  - **Network connections** (source IP, ports, connections)
  - **IP attribution** (most likely source, all detected IPs)
  - **System context** at time of access

### **`iptrack` Command Output:**
```json
{
  "total_tracked_ips": 8,
  "first_tracked": "2024-01-25T10:30:00Z",
  "last_tracked": "2024-01-25T15:45:22Z",
  "recent_activity": 3,
  "ips": [
    {
      "ip": "192.168.1.100",
      "first_seen": "2024-01-25T14:30:22Z",
      "last_seen": "2024-01-25T14:30:22Z",
      "source_pid": 1234,
      "process": "bash",
      "geolocation": {
        "is_private": true,
        "reverse_dns": "attacker-pc.local"
      }
    }
  ]
}
```

---

##  **IP Attribution Features**

### **How honeyFILE Captures Attacker IPs:**

1. **Process Network Analysis**
   - Direct connections from offending process
   - Ancestor process connections (SSH daemon, etc.)
   - Socket enumeration using `ss`/`netstat`

2. **SSH Session Correlation**
   - Active SSH sessions with source IPs
   - SSH daemon process tree traversal
   - Authentication log correlation

3. **Multi-Method Verification**
   - Process connections (`psutil`)
   - Socket enumeration (`ss`, `netstat`)
   - User sessions (`who`, `last`)
   - Network interface analysis

4. **IP Intelligence Database**
   - Persistent IP tracking
   - Timeline analysis
   - Threat intelligence export
   - Geolocation context

### **Example Intrusion Fingerprint with IP:**
```json
{
  "intrusion_id": "abc123def456",
  "event_time": "2024-01-25T14:30:22Z",
  "trigger": {
    "file": "/home/user/.cache/.thumbnails/.sys/.db/Wallet_Recovery_Phrases.txt",
    "pid": 1234,
    "exe": "/usr/bin/bash",
    "comm": "cat"
  },
  "ip_attribution": {
    "all_ips_detected": ["192.168.1.100", "10.0.0.5"],
    "most_likely_source": "192.168.1.100",
    "ip_details": [
      {
        "ip": "192.168.1.100",
        "is_private": true,
        "reverse_dns": "attacker-pc.local",
        "first_seen": "2024-01-25T14:30:22Z",
        "source_pid": 1234,
        "process": "bash",
        "trigger_file": "/home/user/.cache/.thumbnails/.sys/.db/Wallet_Recovery_Phrases.txt"
      }
    ]
  },
  "network_analysis": {
    "process_connections": [
      {
        "remote_ip": "192.168.1.100",
        "remote_port": 22,
        "local_port": 54321,
        "status": "ESTABLISHED"
      }
    ],
    "active_ssh_sessions": [
      {
        "remote_ip": "192.168.1.100",
        "remote_port": 22,
        "user": "attacker",
        "method": "ssh_command"
      }
    ]
  }
}
```

---

##  **Usage Scenarios with IP Attribution**

### **Scenario 1: Remote SSH Intrusion**
```bash
# 1. After breach detection, check for honeyfile access
sudo python3 honeyfile.py report 120

# 2. Export full evidence with IP attribution
sudo python3 honeyfile.py export 120

# 3. Analyze captured IPs
python3 honeyfile.py iptrack list

# 4. Generate threat intelligence for SOC
sudo python3 honeyfile.py export_ips
```

### **Scenario 2: Lateral Movement Detection**
```bash
# 1. Monitor internal network access
sudo python3 honeyfile.py report 30 | jq '.unique_ips_detected'

# 2. Check if internal IPs are accessing decoys
python3 honeyfile.py iptrack timeline

# 3. Analyze process trees for movement patterns
python3 honeyfile.py fingerprint intrusions | jq '.[].network_analysis.process_tree_analysis'
```

### **Scenario 3: Incident Response & Attribution**
```bash
# 1. Capture current state with IP evidence
sudo python3 honeyfile.py export 1440

# 2. Map attacker infrastructure
python3 honeyfile.py iptrack list | jq '.[] | select(.geolocation.is_private == false)'

# 3. Document for law enforcement
python3 honeyfile.py fingerprint intrusions > intrusion_report.json
```

---

##  **Evidence Bundle Structure**

```
evidence/bundle_20240125_143022/
├── audit.log              # Kernel audit logs
├── auth.log               # Authentication logs
├── report.json           # Activity analysis with IPs
├── manifest.json         # Decoy file manifest
├── fingerprints.json     # Historical fingerprints
├── ip_tracking.json     # IP intelligence database
├── system_snapshot.json  # Current system state
└── SHA256SUMS.json      # Cryptographic integrity
```

**New in IP-enhanced version:**
- `ip_tracking.json` - Complete IP attribution database
- Enhanced `report.json` with IP analysis
- Network connection details in fingerprints
- Threat intelligence ready formatting

---

##  **Performance Notes**

- **IP capture** adds minimal overhead (process analysis only during events)
- **Storage requirements**: ~50KB per intrusion fingerprint with IP data
- **Network analysis**: Uses existing system tools (`ss`, `netstat`, `psutil`)
- **Real-time operation**: No continuous network monitoring, only event-triggered analysis

---

##  **Best Practices**

### **Deployment Strategy:**
1. **Initial Deployment**: `init random` + `arm`
2. **Regular Monitoring**: Daily `report 1440` checks
3. **Evidence Collection**: Weekly `export 10080` (7 days)
4. **Rotation Schedule**: Monthly `rotate` or after incidents
5. **IP Intelligence**: Regular `iptrack` reviews

### **IP Tracking Recommendations:**
- Review `iptrack timeline` weekly
- Export `export_ips` for threat intel sharing
- Correlate IPs with firewall/IDS logs
- Use IP data for firewall rule updates

### **Forensic Readiness:**
- Keep evidence bundles on external media
- Document chain of custody
- Use hashes for evidence integrity
- Share IP intelligence with security team

---

##  **Integration Points**

### **With Security Tools:**
- **SIEM Systems**: Import `report.json` and `ip_tracking.json`
- **Firewalls**: Use captured IPs for block lists
- **Threat Intel Platforms**: Import `export_ips` output
- **Incident Response**: Use evidence bundles for documentation

### **Companion Projects:**
- **[network_ids](https://github.com/ekomsSavior/network_ids)** - Network-level detection
- **OSSEC/WAZUH** - Centralized log correlation

---

##  **Legal & Ethical Considerations**

honeyFILE is designed for **defensive security only**:
- Captures only **attacker interaction data**
- Stores **IP addresses for attribution**
- Provides **court-ready evidence**
- Follows **privacy and compliance guidelines**

**Use responsibly:** Only on systems you own or have authorization to monitor.

---

##  **Getting Help**

1. **Check status first**: `python3 honeyfile.py status`
2. **Verify auditd**: `sudo auditctl -l | grep honeyfile`
3. **Review logs**: `sudo ausearch -k honeyfile_tripwire`
4. **Check IP tracking**: `python3 honeyfile.py iptrack`
5. **Open GitHub Issue**: For bugs or feature requests

---
**Author**: ekomsSavior - CERTIFIED ETHICAL HACKER  
---

** Remember**: honeyFILE provides **detection and attribution**, not prevention. Use as part of a layered defense strategy with firewalls, IDS/IPS, and proper access controls.

**When someone touches your honeyfiles, you'll know exactly who they are and where they came from.** 🌐🕵️‍♂️
