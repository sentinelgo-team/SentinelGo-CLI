package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
	"github.com/sentinelgo-team/SentinelGo/internal/scoring"
)

type Report struct {
	GeneratedAt string
	TotalAlerts int
	Alerts      []scoring.ScoredThreat
}

func Generate(threats []scoring.ScoredThreat) {
	r := Report{
		GeneratedAt: time.Now().String(),
		TotalAlerts: len(threats),
		Alerts:      threats,
	}
	file, _ := os.Create("sentinelgo-report.json")
	defer file.Close()
	json.NewEncoder(file).Encode(r)
	fmt.Printf("\nReport saved → sentinelgo-report.json  (%d alerts)\n", len(threats))
}
