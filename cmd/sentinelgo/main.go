package main

import (
	"fmt"
	"os"

	"github.com/sentinelgo-team/SentinelGo/internal/collector"
)

func main() {
	fmt.Println("SentinelGo - Process Enumeration")

	err := collector.ListProcesses()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
