package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sentinelgo-team/SentinelGo/internal/collector"
)

func main() {
	fmt.Println("SentinelGo - Process Enumeration")

	processes, err := collector.GetProcessesFromTasklist()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	jsonData, _ := json.MarshalIndent(processes, "", "  ")
	fmt.Println(string(jsonData))
}
