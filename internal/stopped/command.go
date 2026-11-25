package stopped

import (
	"context"
	"os/exec"
	"time"
)

// waitDelay bounds how long Wait waits for output pipes after the context
// ended and the child was killed.
const waitDelay = 5 * time.Second

// Command is exec.CommandContext for a child that must stop when ctx ends.
// On Unix the child gets its own process group and the whole group is
// killed, so a helper it started cannot keep it running; and Wait stops
// waiting for output after waitDelay, whatever still holds the pipes.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	killGroupOnCancel(cmd)
	cmd.WaitDelay = waitDelay
	return cmd
}
