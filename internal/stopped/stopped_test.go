package stopped

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func expired(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	t.Cleanup(cancel)
	<-ctx.Done()
	return ctx
}

func TestCheckOnlyReportsAnEndedContext(t *testing.T) {
	if err := Check(context.Background()); err != nil {
		t.Fatalf("a live context is not stopped: %v", err)
	}
	err := Check(expired(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestInPhaseNamesTheInnermostStepOnly(t *testing.T) {
	err := InPhase(InPhase(Check(expired(t)), "the malware scan"), "the directory scan")
	var s *Error
	if !errors.As(err, &s) || s.Phase != "the malware scan" {
		t.Fatalf("got %+v", err)
	}
	plain := errors.New("clamscan exited with 2")
	if InPhase(plain, "the malware scan") != plain {
		t.Error("other errors pass unchanged")
	}
	bare := fmt.Errorf("upload: %w", context.DeadlineExceeded)
	if !errors.As(InPhase(bare, "storing the evidence"), &s) || s.Phase != "storing the evidence" {
		t.Errorf("a bare context error gets a phase too: %+v", s)
	}
}

func TestWithProgressKeepsTheLast(t *testing.T) {
	err := WithProgress(WithProgress(InPhase(Check(expired(t)), "the malware scan"), "9 of 9 files read"), "41,233 of 95,150 files scanned")
	var s *Error
	if !errors.As(err, &s) || s.Progress != "41,233 of 95,150 files scanned" || s.Phase != "the malware scan" {
		t.Fatalf("got %+v", s)
	}
	if plain := errors.New("x"); WithProgress(plain, "1 of 2") != plain {
		t.Error("other errors pass unchanged")
	}
}

func TestDescribe(t *testing.T) {
	deep := fmt.Errorf("malware scan of /scan/venv: some/file.h: %w",
		WithProgress(InPhase(Check(expired(t)), "the malware scan"), "41,233 of 95,150 files scanned"))
	msg, ok := Describe(deep, 30*time.Minute, "the scan")
	want := "the scan stopped at its --timeout of 30m0s during the malware scan (41,233 of 95,150 files scanned); raise --timeout"
	if !ok || msg != want {
		t.Fatalf("got %q, want %q", msg, want)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	msg, _ = Describe(InPhase(Check(ctx), "the Trivy scan"), time.Minute, "the scan")
	if msg != "the scan was cancelled during the Trivy scan" {
		t.Errorf("got %q", msg)
	}
	if _, ok := Describe(errors.New("boom"), time.Minute, "the scan"); ok {
		t.Error("other errors are not described")
	}
}

func TestCount(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 95150: "95,150", 1234567: "1,234,567"} {
		if got := Count(n); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}
