//go:build !unix

package stopped

import "os/exec"

// killGroupOnCancel keeps exec.CommandContext's default: kill the child.
func killGroupOnCancel(*exec.Cmd) {}
