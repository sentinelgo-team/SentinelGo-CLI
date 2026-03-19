// SentinelGo-H v5 — Real-Time Behavioral Monitor
//
// Data sources (all work on Windows 11 Home, no admin required):
//   - tasklist     → running processes
//   - netstat -ano → active network connections
//   - Get-EventLog → Windows Application events
//
// Detection rules:
//   1. Suspicious tool running    (watchlist match)
//   2. Abnormal process frequency (baseline deviation)
//   3. New unknown process        (first-time appearance)
//   4. Suspicious network port    (known bad ports)
//   5. High outbound connections  (scanning/exfiltration pattern)
//   6. Tool + network correlation (two signals combined = high confidence)
//
// Usage:
//   go run ./cmd/sentinelgo                     default: runs forever, 3s interval
//   go run ./cmd/sentinelgo -interval 2s        faster scanning
//   go run ./cmd/sentinelgo -cycles 10          stop after 10 cycles
//
// Press Ctrl+C to stop and save the report.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sentinelgo-team/SentinelGo/internal/alert"
	"github.com/sentinelgo-team/SentinelGo/internal/behavior"
	"github.com/sentinelgo-team/SentinelGo/internal/collector"
	"github.com/sentinelgo-team/SentinelGo/internal/parser"
	"github.com/sentinelgo-team/SentinelGo/internal/report"
	"github.com/sentinelgo-team/SentinelGo/internal/scoring"
	"github.com/sentinelgo-team/SentinelGo/internal/state"
)

func main() {
	cycles   := flag.Int("cycles", 0, "cycles to run (0 = forever, stop with Ctrl+C)")
	interval := flag.Duration("interval", 3*time.Second, "seconds between scans")
	flag.Parse()

	printBanner()

	// Initialise pipeline
	st     := state.New()
	engine := behavior.NewEngine()
	scorer := scoring.NewEngine(st)
	rep    := report.NewWriter()

	var allAlerts []alert.AlertRecord
	cycleNum := 0

	// Handle Ctrl+C gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("  Scanning every %s  |  Press Ctrl+C to stop\n\n", *interval)

	for {
		cycleNum++

		// Check for shutdown signal
		select {
		case <-sigCh:
			fmt.Println("\n\n  Shutdown received — saving report...")
			rep.Write(allAlerts, cycleNum-1)
			fmt.Printf("  Total alerts: %d\n\n", len(allAlerts))
			os.Exit(0)
		default:
		}

		// Print cycle header
		fmt.Printf("─── Cycle %d", cycleNum)
		if *cycles > 0 {
			fmt.Printf("/%d", *cycles)
		}
		fmt.Printf("  [%s]", time.Now().Format("15:04:05"))
		if st.CycleCount < state.MinBaselineCycles {
			fmt.Printf("  [LEARNING baseline: %d/%d]",
				st.CycleCount+1, state.MinBaselineCycles)
		}
		fmt.Println()

		// ── Step 1: Collect ──────────────────────────────────────────────
		procs, err := collector.CollectProcesses()
		if err != nil {
			fmt.Printf("  [!] Process collection error: %v\n", err)
		}

		conns, err := collector.CollectConnections()
		if err != nil {
			fmt.Printf("  [!] Network collection error: %v\n", err)
		}

		events := collector.CollectAppEvents()

		fmt.Printf("  Processes: %-4d  |  Connections: %-4d  |  Events: %d\n",
			len(procs), len(conns), len(events))

		// ── Step 2: Parse ────────────────────────────────────────────────
		parsed := parser.Parse(procs, conns, events)

		// ── Step 3: Update State ─────────────────────────────────────────
		st.Update(parsed)

		// ── Step 4: Detect ───────────────────────────────────────────────
		detections := engine.Analyze(st)
		scored := scorer.Score(detections)

		if len(scored) == 0 {
			fmt.Println("  ✓  Clean — no threats detected")
		} else {
			fmt.Printf("  ⚠  %d threat(s) detected\n", len(scored))
			cycleAlerts := alert.Emit(scored)
			allAlerts = append(allAlerts, cycleAlerts...)
		}

		// Check if done
		if *cycles > 0 && cycleNum >= *cycles {
			break
		}

		time.Sleep(*interval)
	}

	// Final report
	rep.Write(allAlerts, cycleNum)
	fmt.Printf("\n  Done.  Cycles: %d  |  Total alerts: %d\n\n",
		cycleNum, len(allAlerts))
}

func printBanner() {
	fmt.Println(`
  ╔════════════════════════════════════════════════════════════╗
  ║   SentinelGo-H  v5  |  Real-Time Behavioral Monitor       ║
  ║   Sources: Processes + Network + Events                    ║
  ║   Detection: Watchlist + Baseline + Anomaly + Correlation  ║
  ╚════════════════════════════════════════════════════════════╝`)
}
