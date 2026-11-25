//go:build unix

package stopped

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestCommandStopsTheChildAndWhatItStarted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// The shell's own child keeps the output pipe open after the shell dies.
	cmd := Command(ctx, "sh", "-c", "sleep 10 & wait")
	start := time.Now()
	_, err := cmd.Output()
	if err == nil || !errors.Is(Check(ctx), context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the command ran on for %s after the deadline", took)
	}
}

// Stopped blames the context only when it stopped the command: its Cancel
// fired, or the command never started. How the child ended (an exit
// status, a signal of its own) does not decide it, since exit codes differ
// between platforms: on Windows a killed child exits with 1, which for
// clamscan means "virus found".
func TestStoppedOnlyWhenTheContextStoppedTheCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cmd := Command(ctx, "sleep", "10")
	if err := cmd.Stopped(cmd.Run()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("killed at the deadline: got %v", err)
	}
	for _, script := range []string{"exit 2", "kill -9 $$"} {
		ctx, cancel := context.WithCancel(context.Background())
		cmd := Command(ctx, "sh", "-c", script)
		err := cmd.Run()
		cancel() // the context ends after the command failed by itself
		if err == nil || cmd.Stopped(err) != nil {
			t.Errorf("%s: a command that ended by itself failed by itself: %v", script, cmd.Stopped(err))
		}
	}
	ended, cancelEnded := context.WithCancel(context.Background())
	cancelEnded()
	cmd = Command(ended, "sh", "-c", "exit 0")
	if err := cmd.Stopped(cmd.Run()); !errors.Is(err, context.Canceled) {
		t.Errorf("never started: got %v", err)
	}
	if Command(ended, "true").Stopped(nil) != nil {
		t.Error("no error, no stop")
	}
}

// Cancelling a command whose process group is already gone is not an
// error: exec treats os.ErrProcessDone as "nothing left to stop".
func TestCancelAfterTheGroupIsGone(t *testing.T) {
	cmd := Command(context.Background(), "sh", "-c", "exit 0")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("got %v", err)
	}
}
