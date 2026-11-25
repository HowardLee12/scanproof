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
	err := InPhase(InPhase(Check(expired(t)), "during the malware scan"), "during the directory scan")
	var s *Error
	if !errors.As(err, &s) || s.Phase != "during the malware scan" {
		t.Fatalf("got %+v", err)
	}
	plain := errors.New("clamscan exited with 2")
	if InPhase(plain, "during the malware scan") != plain {
		t.Error("other errors pass unchanged")
	}
	// A timeout inside a step (an SDK's own credential lookup, an HTTP
	// client's Timeout) is not the scan's deadline: only Check makes a stop.
	inner := fmt.Errorf("upload: get credentials: %w", context.DeadlineExceeded)
	if InPhase(inner, "while storing the evidence") != inner {
		t.Error("a wrapped context error that Check did not make passes unchanged")
	}
}

func TestWithProgressKeepsTheLast(t *testing.T) {
	err := WithProgress(WithProgress(InPhase(Check(expired(t)), "during the malware scan"), "9 of 9 files read"), "41,233 of 95,150 files scanned")
	var s *Error
	if !errors.As(err, &s) || s.Progress != "41,233 of 95,150 files scanned" || s.Phase != "during the malware scan" {
		t.Fatalf("got %+v", s)
	}
	if plain := errors.New("x"); WithProgress(plain, "1 of 2") != plain {
		t.Error("other errors pass unchanged")
	}
}

func TestDescribe(t *testing.T) {
	deep := fmt.Errorf("malware scan of /scan/venv: some/file.h: %w",
		WithProgress(InPhase(Check(expired(t)), "during the malware scan"), "41,233 of 95,150 files scanned"))
	msg, ok := Describe(deep, 30*time.Minute, "the scan")
	want := "the scan stopped at its --timeout of 30m0s during the malware scan (41,233 of 95,150 files scanned); raise --timeout"
	if !ok || msg != want {
		t.Fatalf("got %q, want %q", msg, want)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	msg, _ = Describe(InPhase(Check(ctx), "during the Trivy scan"), time.Minute, "the scan")
	if msg != "the scan was cancelled during the Trivy scan" {
		t.Errorf("got %q", msg)
	}
	// A phase says its own preposition.
	msg, _ = Describe(InPhase(Check(expired(t)), "while making the PDF"), time.Minute, "the scan")
	if msg != "the scan stopped at its --timeout of 1m0s while making the PDF; raise --timeout" {
		t.Errorf("got %q", msg)
	}
	if _, ok := Describe(errors.New("boom"), time.Minute, "the scan"); ok {
		t.Error("other errors are not described")
	}
	inner := fmt.Errorf("operation error ec2imds: GetMetadata: %w", context.DeadlineExceeded)
	if _, ok := Describe(inner, time.Minute, "the scan"); ok {
		t.Error("a timeout inside a step, while the scan's deadline has not passed, is not a stop")
	}
}

func TestCause(t *testing.T) {
	inner := fmt.Errorf("get credentials: %w", context.DeadlineExceeded)
	if Cause(context.Background(), inner) != inner {
		t.Error("while the scan's context is live, an error is what it says")
	}
	if Cause(expired(t), errors.New("clamscan exited with 2")).Error() != "clamscan exited with 2" {
		t.Error("an error that is not about a context is kept even after the deadline")
	}
	var s *Error
	if err := Cause(expired(t), fmt.Errorf("list: %w", context.DeadlineExceeded)); !errors.As(err, &s) ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a context error after the scan's deadline passed is the stop: %v", err)
	}
	named := InPhase(Check(expired(t)), "during the malware scan")
	if Cause(expired(t), named) != named {
		t.Error("a stop is kept as it is")
	}
	if Cause(context.Background(), nil) != nil {
		t.Error("no error, no cause")
	}
}

func TestCount(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 95150: "95,150", 1234567: "1,234,567"} {
		if got := Count(n); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{0: "0 files", 1: "1 file", 2: "2 files", 95150: "95,150 files"} {
		if got := Plural(n, "file", "files"); got != want {
			t.Errorf("Plural(%d) = %q, want %q", n, got, want)
		}
	}
}
