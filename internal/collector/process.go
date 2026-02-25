package collector

import (
	"fmt"
	"os/exec"
)

func ListProcesses() error {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
