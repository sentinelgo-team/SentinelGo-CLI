// Package parser normalises raw collector output into clean structs
// ready for the State Engine.
package parser

import (
	"github.com/sentinelgo-team/SentinelGo/internal/collector"
	"time"
)

// ParsedProcess is a normalised process record.
type ParsedProcess struct {
	Name      string
	PID       string
	Memory    string
	Timestamp time.Time
}

// ParsedConnection is a normalised network connection.
type ParsedConnection struct {
	Protocol      string
	LocalPort     string
	RemoteAddress string
	RemotePort    string
	State         string
	PID           string
	Suspicious    bool // true if remote port is on suspicious list
	Timestamp     time.Time
}

// ParsedEvent is a normalised application event.
type ParsedEvent struct {
	EventID   int
	Source    string
	Message   string
	Timestamp time.Time
}

// ParseResult bundles all three parsed streams.
type ParseResult struct {
	Processes   []ParsedProcess
	Connections []ParsedConnection
	Events      []ParsedEvent
}

// Parse normalises all three raw collector streams.
func Parse(
	procs []collector.Process,
	conns []collector.Connection,
	events []collector.AppEvent,
) ParseResult {
	return ParseResult{
		Processes:   parseProcesses(procs),
		Connections: parseConnections(conns),
		Events:      parseEvents(events),
	}
}

func parseProcesses(procs []collector.Process) []ParsedProcess {
	out := make([]ParsedProcess, 0, len(procs))
	for _, p := range procs {
		out = append(out, ParsedProcess{
			Name:      p.Name,
			PID:       p.PID,
			Memory:    p.Memory,
			Timestamp: p.Timestamp,
		})
	}
	return out
}

func parseConnections(conns []collector.Connection) []ParsedConnection {
	out := make([]ParsedConnection, 0, len(conns))
	for _, c := range conns {
		suspicious := collector.SuspiciousPorts[c.RemotePort] ||
			collector.SuspiciousPorts[c.LocalPort]
		// Only include ESTABLISHED connections and listeners — skip TIME_WAIT noise
		if c.State == "TIME_WAIT" || c.State == "CLOSE_WAIT" {
			continue
		}
		out = append(out, ParsedConnection{
			Protocol:      c.Protocol,
			LocalPort:     c.LocalPort,
			RemoteAddress: c.RemoteAddress,
			RemotePort:    c.RemotePort,
			State:         c.State,
			PID:           c.PID,
			Suspicious:    suspicious,
			Timestamp:     c.Timestamp,
		})
	}
	return out
}

func parseEvents(events []collector.AppEvent) []ParsedEvent {
	out := make([]ParsedEvent, 0, len(events))
	for _, e := range events {
		out = append(out, ParsedEvent{
			EventID:   e.EventID,
			Source:    e.Source,
			Message:   e.Message,
			Timestamp: e.Timestamp,
		})
	}
	return out
}
