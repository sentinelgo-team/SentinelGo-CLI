package alert

import (
	"encoding/json"
	"fmt"
	"os"
	"github.com/sentinelgo-team/SentinelGo/internal/scoring"
)

func Emit(threats []scoring.ScoredThreat) {
	file, _ := os.Create("sentinelgo-alerts.json")
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, t := range threats {
		fmt.Printf("[ALERT] Process:%s PID:%s Threat:%s Score:%d Severity:%s\n",
			t.Name, t.PID, t.Threat, t.Score, t.Severity)
		encoder.Encode(t)
	}
}
