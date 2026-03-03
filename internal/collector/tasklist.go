import (
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func GetProcessesFromTasklist() ([]ProcessInfo, error) {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(string(output)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	for _, record := range records {
		if len(record) < 5 {
			continue // skip malformed line
		}

		pid, _ := strconv.Atoi(record[1])
		sessionID, _ := strconv.Atoi(record[3])

		processes = append(processes, ProcessInfo{
			Name:        record[0],
			PID:         pid,
			SessionName: record[2],
			SessionID:   sessionID,
			MemoryUsage: record[4],
		})
	}

	return processes, nil
}
