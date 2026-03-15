package collector

import (
	"bufio"
	"os/exec"
	"strings"
)

type Process struct {
	Name   string `json:"name"`
	PID    string `json:"pid"`
	Memory string `json:"memory"`
}

func GetProcessesFromTasklist() ([]Process, error) {
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []Process
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, "\"", "")
		parts := strings.Split(line, ",")
		if len(parts) >= 5 {
			processes = append(processes, Process{
				Name:   parts[0],
				PID:    parts[1],
				Memory: parts[4],
			})
		}
	}

	return processes, nil
}
