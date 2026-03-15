package parser

import "github.com/sentinelgo-team/SentinelGo/internal/collector"

type ParsedProcess struct {
	Name       string
	PID        string
	Memory     string
	Suspicious bool
}

var watchlist = map[string]bool{
	"mimikatz.exe":   true,
	"psexec.exe":     true,
	"nc.exe":         true,
	"pwdump.exe":     true,
	"powershell.exe": true,
	"cmd.exe":        true,
	"certutil.exe":   true,
	"mshta.exe":      true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"rundll32.exe":   true,
}

func Parse(processes []collector.Process) []ParsedProcess {
	var parsed []ParsedProcess
	for _, p := range processes {
		parsed = append(parsed, ParsedProcess{
			Name:       p.Name,
			PID:        p.PID,
			Memory:     p.Memory,
			Suspicious: watchlist[p.Name],
		})
	}
	return parsed
}
