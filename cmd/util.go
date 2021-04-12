package cmd

import (
	"os"
	"os/exec"
)

// cacheSudo runs `sudo -v` so that subsequent commands can be run with sudo without user interaction
func cacheSudo() error {
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
