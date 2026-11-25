//go:build unix

package stopped

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

// exitError runs a shell command that fails and returns its error.
func exitError(t *testing.T, script string) error {
	t.Helper()
	err := exec.Command("sh", "-c", script).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("%s: got %v", script, err)
	}
	return err
}

func TestKilledOnlyBlamesTheStopForAKill(t *testing.T) {
	ended := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	exited := exitError(t, "exit 2")
	signalled := exitError(t, "kill -9 $$")
	if Killed(ended(), exited) != nil {
		t.Error("a command that exited with a status of its own failed by itself")
	}
	if !errors.Is(Killed(ended(), signalled), context.Canceled) {
		t.Error("a command killed after the context ended was stopped")
	}
	if !errors.Is(Killed(ended(), fmt.Errorf("start: %w", errors.New("broken pipe"))), context.Canceled) {
		t.Error("a command that did not run to completion after the context ended was stopped")
	}
	if Killed(context.Background(), signalled) != nil || Killed(ended(), nil) != nil {
		t.Error("no stop without an ended context and an error")
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
