package stopped

import (
	"context"
	"errors"
	"os/exec"
	"sync/atomic"
	"time"
)

// waitDelay bounds how long Wait waits for output pipes after the context
// ended and the child was killed.
const waitDelay = 5 * time.Second

// Cmd is an exec.Cmd that remembers whether its context stopped it.
type Cmd struct {
	*exec.Cmd
	ctx       context.Context
	cancelled atomic.Bool
}

// Command is exec.CommandContext for a child that must stop when ctx ends.
// On Unix the child gets its own process group and the whole group is
// killed, so a helper it started cannot keep it running; and Wait stops
// waiting for output after waitDelay, whatever still holds the pipes.
func Command(ctx context.Context, name string, args ...string) *Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	c := &Cmd{Cmd: cmd, ctx: ctx}
	kill := killFunc(cmd)
	cmd.Cancel = func() error {
		c.cancelled.Store(true)
		return kill()
	}
	cmd.WaitDelay = waitDelay
	return c
}

// Stopped returns the stop when the command failed because its context
// ended: it was killed for it, or never started. A command that ended by
// itself, with an exit status or a signal of its own, failed by itself,
// even if the context ended a moment later. This does not look at exit
// codes, which differ between platforms (a killed child exits with 1 on
// Windows, and for clamscan 1 means "virus found").
func (c *Cmd) Stopped(err error) error {
	stop := Check(c.ctx)
	if err == nil || stop == nil {
		return nil
	}
	if c.cancelled.Load() || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return stop
	}
	return nil
}
