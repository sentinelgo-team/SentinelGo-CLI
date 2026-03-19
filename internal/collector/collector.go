// Package collector gathers three real data streams from Windows:
//   (A) Processes   — tasklist /fo csv
//   (B) Network     — netstat -ano
//   (C) App Events  — PowerShell Get-EventLog Application
//
// No Security log access required. No admin rights required.
// All data is real — nothing is simulated.
package collector

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ── Process ───────────────────────────────────────────────────────────────

// Process is one row from tasklist.
type Process struct {
	Name      string
	PID       string
	Memory    string
	Timestamp time.Time
}

// CollectProcesses runs tasklist and returns all running processes.
func CollectProcesses() ([]Process, error) {
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var procs []Process
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	now := time.Now()
	for scanner.Scan() {
		line := strings.ReplaceAll(scanner.Text(), `"`, "")
		parts := strings.Split(line, ",")
		if len(parts) >= 5 {
			procs = append(procs, Process{
				Name:      strings.ToLower(strings.TrimSpace(parts[0])),
				PID:       strings.TrimSpace(parts[1]),
				Memory:    strings.TrimSpace(parts[4]),
				Timestamp: now,
			})
		}
	}
	return procs, nil
}

// ── Network Connection ────────────────────────────────────────────────────

// Connection is one row from netstat -ano.
type Connection struct {
	Protocol      string
	LocalAddress  string
	LocalPort     string
	RemoteAddress string
	RemotePort    string
	State         string
	PID           string
	Timestamp     time.Time
}

// CollectConnections runs netstat and returns active network connections.
func CollectConnections() ([]Connection, error) {
	cmd := exec.Command("netstat", "-ano")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var conns []Connection
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	now := time.Now()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip headers and empty lines
		if line == "" ||
			strings.HasPrefix(line, "Active") ||
			strings.HasPrefix(line, "Proto") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := fields[0]
		local := fields[1]
		remote := fields[2]
		// State and PID positions differ for TCP vs UDP
		state := ""
		pid := ""
		if proto == "TCP" && len(fields) >= 5 {
			state = fields[3]
			pid = fields[4]
		} else if proto == "UDP" && len(fields) >= 4 {
			pid = fields[3]
		}
		localAddr, localPort := splitAddrPort(local)
		remoteAddr, remotePort := splitAddrPort(remote)
		conns = append(conns, Connection{
			Protocol:      proto,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			State:         state,
			PID:           pid,
			Timestamp:     now,
		})
	}
	return conns, nil
}

// splitAddrPort splits "192.168.1.1:443" into ("192.168.1.1", "443").
// Handles IPv6 addresses like "[::1]:80".
func splitAddrPort(addr string) (string, string) {
	if strings.HasPrefix(addr, "[") {
		// IPv6
		end := strings.LastIndex(addr, "]")
		if end < 0 {
			return addr, ""
		}
		ip := addr[1:end]
		port := ""
		if end+2 < len(addr) {
			port = addr[end+2:]
		}
		return ip, port
	}
	last := strings.LastIndex(addr, ":")
	if last < 0 {
		return addr, ""
	}
	return addr[:last], addr[last+1:]
}

// ── Application Event ─────────────────────────────────────────────────────

// AppEvent is one Windows Application log entry (no admin required).
type AppEvent struct {
	EventID   int
	Source    string
	Message   string
	Timestamp time.Time
}

// CollectAppEvents reads the Windows Application event log via PowerShell.
// This works on Windows 11 Home without administrator privileges.
func CollectAppEvents() []AppEvent {
	script := `
Get-EventLog -LogName Application -Newest 30 |
Select-Object EventID, Source, Message |
ForEach-Object {
    $msg = $_.Message -replace '\r?\n',' ' -replace ',',' '
    "$($_.EventID)|||$($_.Source)|||$msg"
}
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var events []AppEvent
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	now := time.Now()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|||", 3)
		if len(parts) < 3 {
			continue
		}
		id, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		events = append(events, AppEvent{
			EventID:   id,
			Source:    strings.TrimSpace(parts[1]),
			Message:   strings.TrimSpace(parts[2]),
			Timestamp: now,
		})
	}
	return events
}

// ── Suspicious indicators ─────────────────────────────────────────────────

// SuspiciousProcesses is the watchlist of known offensive tool names.
var SuspiciousProcesses = map[string]bool{
	"mimikatz.exe":   true,
	"psexec.exe":     true,
	"nc.exe":         true,
	"ncat.exe":       true,
	"netcat.exe":     true,
	"pwdump.exe":     true,
	"wce.exe":        true,
	"fgdump.exe":     true,
	"powershell.exe": true,
	"cmd.exe":        true,
	"certutil.exe":   true,
	"mshta.exe":      true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"rundll32.exe":   true,
	"regsvr32.exe":   true,
	"msiexec.exe":    true,
}

// SuspiciousPorts are ports commonly used by malware or C2 frameworks.
var SuspiciousPorts = map[string]bool{
	"4444":  true, // Metasploit default
	"1234":  true, // common reverse shell
	"9001":  true, // Tor
	"9050":  true, // Tor SOCKS
	"1337":  true, // common hacker port
	"31337": true, // elite/backdoor
	"6666":  true, // IRC/botnet
	"6667":  true, // IRC/botnet
}
