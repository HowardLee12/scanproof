package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/stopped"
)

// waitForDeadline behaves like a Trivy that is killed when the context ends.
func waitForDeadline(ctx context.Context, _ string, args ...string) ([]byte, error) {
	if args[0] == "version" {
		return []byte(`{"Version":"0.76.2"}`), nil
	}
	<-ctx.Done()
	return nil, errors.New("signal: killed: ")
}

func shortContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestRunnerReportsTheDeadlineAndThePhase(t *testing.T) {
	r := Runner{Bin: "trivy", exec: waitForDeadline}
	cases := map[string]func(context.Context) error{
		"the Trivy scan":      func(ctx context.Context) error { _, err := r.Scan(ctx, "alpine:3.18.0"); return err },
		"the Trivy scan ":     func(ctx context.Context) error { _, err := r.ScanRootfs(ctx, "/srv/app"); return err },
		"the Trivy SBOM scan": func(ctx context.Context) error { _, err := r.ScanSBOM(ctx, []byte("{}")); return err },
		"the SBOM conversion": func(ctx context.Context) error { _, err := r.SBOM(ctx, []byte("{}")); return err },
	}
	for phase, run := range cases {
		err := run(shortContext(t))
		var s *stopped.Error
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &s) || s.Phase != strings.TrimSpace(phase) {
			t.Errorf("%s: got %v", phase, err)
		}
		if strings.Contains(err.Error(), "signal: killed") {
			t.Errorf("%s: the deadline is the cause, not the signal: %v", phase, err)
		}
	}
}

func TestRunnerReportsTrivysOwnTimeout(t *testing.T) {
	exec := func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("exit status 1: FATAL run error: rootfs scan error: scan failed: failed analysis: " +
			"analyze file (config/settings.ini): semaphore acquire: context deadline exceeded")
	}
	_, err := Runner{Bin: "trivy", exec: exec}.ScanRootfs(context.Background(), "/srv/app")
	msg, ok := stopped.Describe(err, 30*time.Minute, "the scan")
	if !ok || !strings.Contains(msg, "during the Trivy scan") || strings.Contains(msg, "settings.ini") {
		t.Fatalf("Trivy reaching its own --timeout is a timeout, not a problem with one file: %q (%v)", msg, err)
	}
}

func TestRunnerKeepsAFailureBeforeTheDeadline(t *testing.T) {
	exec := func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("exit status 1: no such image")
	}
	_, err := Runner{Bin: "trivy", exec: exec}.Scan(shortContext(t), "missing:1")
	var s *stopped.Error
	if errors.As(err, &s) || !strings.Contains(err.Error(), "no such image") {
		t.Fatalf("got %v", err)
	}
}

func TestDefaultExecIsStoppedByTheDeadline(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n[ \"$1\" = version ] && exit 1\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := NewRunner(bin, time.Minute).ScanRootfs(shortContext(t), "/srv/app")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}
}
