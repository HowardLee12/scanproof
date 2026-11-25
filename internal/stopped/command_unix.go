//go:build unix

package stopped

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killGroupOnCancel puts the child in its own process group and kills the
// whole group when the context ends, so a helper it started cannot keep the
// scan waiting. The other side of that: signals sent to ScanProof's own
// process group (Ctrl-C in a terminal, a CI runner stopping the job) do not
// reach the child directly. ScanProof catches SIGINT and SIGTERM, ends its
// context and so kills the group; only a SIGKILL to ScanProof itself
// leaves the child running. The child gets SIGKILL straight away: the
// scanners keep no state worth flushing, and ScanProof removes their work
// directories itself.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone // the group has already gone
		}
		return err
	}
}
