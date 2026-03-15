package main

import (
	"fmt"
	"github.com/sentinelgo-team/SentinelGo/internal/alert"
	"github.com/sentinelgo-team/SentinelGo/internal/analyzer"
	"github.com/sentinelgo-team/SentinelGo/internal/collector"
	"github.com/sentinelgo-team/SentinelGo/internal/parser"
	"github.com/sentinelgo-team/SentinelGo/internal/report"
	"github.com/sentinelgo-team/SentinelGo/internal/scoring"
)

func main() {
	fmt.Println("SentinelGo-H  |  Live Process Monitor  |  Starting...")
	fmt.Println()

	processes, err := collector.GetProcessesFromTasklist()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("[COLLECTOR]  %d processes found\n", len(processes))

	parsed := parser.Parse(processes)
	fmt.Printf("[PARSER]     %d processes parsed\n", len(parsed))

	detections := analyzer.Analyze(parsed)
	fmt.Printf("[ANALYZER]   %d detection(s)\n", len(detections))

	scored := scoring.Score(detections)

	fmt.Println()
	alert.Emit(scored)
	report.Generate(scored)

	fmt.Println("\nMonitoring session complete.")
}
