package analyzer

import "github.com/sentinelgo-team/SentinelGo/internal/parser"

type Detection struct {
	Name   string
	PID    string
	Threat string
}

func Analyze(processes []parser.ParsedProcess) []Detection {
	var detections []Detection
	for _, p := range processes {
		if p.Suspicious {
			detections = append(detections, Detection{
				Name:   p.Name,
				PID:    p.PID,
				Threat: "suspicious_process",
			})
		}
	}
	return detections
}
