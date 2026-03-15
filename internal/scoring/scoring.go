package scoring

import "github.com/sentinelgo-team/SentinelGo/internal/analyzer"

type ScoredThreat struct {
	Name     string
	PID      string
	Threat   string
	Score    int
	Severity string
}

func Score(detections []analyzer.Detection) []ScoredThreat {
	var scored []ScoredThreat
	for _, d := range detections {
		score := 40
		severity := "MEDIUM"
		scored = append(scored, ScoredThreat{
			Name:     d.Name,
			PID:      d.PID,
			Threat:   d.Threat,
			Score:    score,
			Severity: severity,
		})
	}
	return scored
}
