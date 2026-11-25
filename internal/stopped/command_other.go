//go:build !unix

package stopped

import "os/exec"

// killFunc kills the child, as exec.CommandContext does by default.
func killFunc(cmd *exec.Cmd) func() error {
	return func() error { return cmd.Process.Kill() }
}
