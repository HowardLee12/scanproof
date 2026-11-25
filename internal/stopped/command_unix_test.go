//go:build unix

package stopped

import (
	"context"
	"errors"
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
