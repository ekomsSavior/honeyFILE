# honeyFILE 

**Defensive honeyFILE Tripwire for Linux with Advanced Fingerprinting**

`honeyFILE` is a **legal, non-harmful defensive deception tool** that plants decoy files ("honeyfiles") in **realistic hidden locations** on your system, uses **kernel-level auditing** to alert you when someone accesses them, and provides **advanced forensic fingerprinting** for incident response.

---

##  What honeyFILE Does

* Creates **decoy files** that look valuable to an intruder
* Places them in **sneaky but believable locations** under the user's home directory
* Uses **auditd** to log all access attempts with full forensic context
* Performs **system fingerprinting** to establish baseline system state
* Generates **intrusion fingerprints** with detailed attacker context
* Creates **forensic evidence bundles** with cryptographic integrity
* Supports **randomized rotation** to prevent pattern recognition
* **New**: Advanced fingerprinting for attribution and root cause analysis

---

##  Threat Model

honeyFILE is designed to detect:

* Unauthorized local file browsing
* Post-compromise attacker curiosity
* SSH intrusions (password or key-based)
* Lateral movement reconnaissance
* "Living off the land" attackers poking around user data
* Insider threats accessing sensitive-looking files
* Persistence mechanism discovery

It is **not** meant to stop the intrusion by itself — it provides **early detection, attribution, and forensic evidence**.

---

##  Dependencies

### System Packages
```bash

sudo apt update
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
```

### Python Requirements
```bash
# Option 1: Global install (with --break-system-packages)
pip install psutil --break-system-packages

# Option 2: Virtual environment 
python3 -m venv venv
source venv/bin/activate
pip install psutil --break-system-packages
```

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
```
or 

```bash
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

## Commands Reference

### Basic Operations
```bash
# Initialize with random location
python3 honeyfile.py init random

# Initialize with fixed location
python3 honeyfile.py init fixed <path>

# Arm auditd monitoring (requires sudo)
sudo python3 honeyfile.py arm

# Check system status
python3 honeyfile.py status

# Generate activity report for last N minutes
sudo python3 honeyfile.py report <minutes>

# Export forensic evidence bundle
sudo python3 honeyfile.py export <minutes>

# Rotate to new random location
sudo python3 honeyfile.py rotate
```

###  Fingerprinting Commands
```bash
# Show fingerprint summary
python3 honeyfile.py fingerprint

# View all system fingerprints (historical snapshots)
python3 honeyfile.py fingerprint system

# View all intrusion fingerprints
python3 honeyfile.py fingerprint intrusions

# Compare latest system fingerprints for changes
python3 honeyfile.py fingerprint compare

# Take new system snapshot
python3 honeyfile.py fingerprint snapshot
```

---

## Advanced Fingerprinting Features

### System Fingerprinting
Captures comprehensive system state including:
- **Hardware fingerprints** (MAC addresses, CPU, memory)
- **Network configuration** (IPs, interfaces, routes)
- **User and process information**
- **Filesystem layout and mount points**
- **System uptime and load averages**

### Intrusion Fingerprinting
When an access occurs, honeyFILE captures:
- **Process details** (PID, command line, parent/child relationships)
- **Network connections** of the suspicious process
- **Open file handles** at time of access
- **Execution context** (UID, GID, SELinux context)
- **Pattern detection** for known attack tools

### Forensic Artifacts
- **Timeline correlation** between system changes and intrusions
- **Hash-based integrity** for all evidence
- **JSON-structured** evidence for easy parsing
- **Automated bundle creation** with cryptographic verification

---

## Example Usage Scenarios

### Scenario 1: SSH Intrusion Detection
```bash
# 1. After potential breach, check for honeyfile access
sudo python3 honeyfile.py report 120

# 2. If access detected, export full evidence
sudo python3 honeyfile.py export 120

# 3. Analyze fingerprints for attribution
python3 honeyfile.py fingerprint intrusions
```

### Scenario 2: Insider Threat Monitoring
```bash
# 1. Deploy honeyfiles in sensitive directories
python3 honeyfile.py init fixed ~/Documents/financial_records/.backup

# 2. Monitor regularly
sudo python3 honeyfile.py report 30 | jq '.audit_events'

# 3. Compare system state before/after incidents
python3 honeyfile.py fingerprint compare
```

### Scenario 3: Incident Response
```bash
# 1. During IR, capture current state
sudo python3 honeyfile.py export 1440  # Last 24 hours
python3 honeyfile.py fingerprint snapshot

# 2. Analyze network connections from intrusion fingerprints
python3 honeyfile.py fingerprint intrusions | jq '.[].trigger.process_details.connections'
```

---

## Evidence Bundle Structure

```
evidence/bundle_20240125_143022/
├── audit.log              # Kernel audit logs
├── auth.log               # Authentication logs
├── report.json           # Activity analysis
├── manifest.json         # Decoy file manifest
├── fingerprints.json     # Historical fingerprints
├── system_snapshot.json  # Current system state
└── SHA256SUMS.json      # Cryptographic integrity
```

Each bundle includes:
- **Tamper-evident** hash verification
- **Timeline correlation** between events
- **System context** at time of capture
- **Legal-ready** JSON formatting

---

## Legal & Ethical Stance

honeyFILE follows **defensive security best practices**:

* Evidence is generated by the OS kernel
* No interaction with attacker systems
* No retaliation or exploitation
* Clearly labeled "DECOY" content
* Suitable for IR, SOC, and LE handoff

---

##  Technical Architecture

### 1. **Decoy Layer**
- Random/fixed hidden locations
- Believable file names and content
- Clear "DECOY" labeling for legal protection

### 2. **Monitoring Layer**
- Linux Audit Framework (auditd)
- Kernel-level event capture
- Correlated SSH authentication

### 3. **Fingerprinting Layer**
- System state snapshots
- Intrusion context capture
- Pattern-based threat detection

### 4. **Forensics Layer**
- Evidence bundling
- Cryptographic integrity
- Timeline reconstruction

---

##  Decoy File Themes

honeyFILE uses **safe, clearly labeled DECOY content**, such as:

* **Wallet recovery phrases** (fake seed phrases)
* **Exchange API keys** (fake credentials)
* **VPN configuration backups** (fake configs)
* **Database credentials** (fake connection strings)
* **SSH private keys** (fake key material)

All files contain **"DECOY FILE — NOT REAL SECRETS"** headers and cause **no harm** if exfiltrated.

---

##  Rotation Strategy

### When to Rotate
- After suspected compromise
- Every 30-90 days (operational security)
- Before security assessments
- When deploying to new systems

### Rotation Benefits
```bash
# Rotate to new random location
sudo python3 honeyfile.py rotate

# This will:
# 1. Remove old audit rules
# 2. Create new decoy location
# 3. Update manifest
# 4. Install new audit rules
```

---


## Related Projects

* [`network_ids`](https://github.com/ekomsSavior/network_ids)
  Network-level detection and response (great companion tool)

* `osquery` – System instrumentation
* `auditbeat` – Auditd metrics for Elastic
* `canarytokens` – Web-based honey tokens

---

##  Author

**ekomsSavior**
** CERTIFIED ETHICAL HACKER**

