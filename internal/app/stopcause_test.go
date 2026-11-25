package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/store"
)

// putFailingStore fails every Put with err.
type putFailingStore struct {
	store.Store
	err error
}

func (s putFailingStore) Put(context.Context, string, []byte, string) error { return s.err }

// A timeout inside a step, such as the AWS SDK giving up on the instance
// metadata service after its own 5 seconds, is that step's failure, not
// the scan reaching its --timeout.
func TestATimeoutInsideAStepIsNotTheScansTimeout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, resultsFile), "{}")
	imds := fmt.Errorf("get credentials: operation error ec2imds: GetMetadata: %w", context.DeadlineExceeded)
	err := uploadFiles(context.Background(), putFailingStore{err: imds}, dir, "scans/x/", []string{resultsFile})
	msg := describeStop(err, 30*time.Minute, "the scan").Error()
	if !strings.Contains(msg, "ec2imds: GetMetadata") || strings.Contains(msg, "--timeout") {
		t.Fatalf("the real error must be shown: %q", msg)
	}
}

func TestAContextErrorAfterTheDeadlineIsTheStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, resultsFile), "{}")
	err := uploadFiles(ctx, putFailingStore{err: fmt.Errorf("put: %w", context.Canceled)}, dir, "scans/x/", []string{resultsFile})
	if msg := describeStop(err, time.Minute, "the scan").Error(); !strings.HasPrefix(msg, "the scan was cancelled") ||
		!strings.Contains(msg, "storing the evidence") {
		t.Fatalf("got %q", msg)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
