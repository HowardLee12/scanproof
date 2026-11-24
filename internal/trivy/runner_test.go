package trivy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeExec struct {
	calls   [][]string
	outputs map[string][]byte
	err     error
}

func (f *fakeExec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.err != nil {
		return nil, f.err
	}
	return f.outputs[args[0]], nil
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRunnerScanRunsTrivyAndAddsDatabaseTime(t *testing.T) {
	fake := &fakeExec{outputs: map[string][]byte{
		"image":   readFixture(t, "trivy-alpine-3.18.0.json"),
		"version": readFixture(t, "trivy-version.json"),
	}}
	r := Runner{Bin: "/usr/bin/trivy", exec: fake.run}

	res, err := r.Scan(context.Background(), "alpine:3.18.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 trivy calls, got %d", len(fake.calls))
	}
	scan := strings.Join(fake.calls[0], " ")
	for _, want := range []string{"/usr/bin/trivy image", "--format json", "--scanners vuln,secret", "alpine:3.18.0"} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan command %q is missing %q", scan, want)
		}
	}
	if res.Scanner.DBUpdatedAt == nil {
		t.Error("database update time should come from `trivy version`")
	}
}

func TestRunnerScanReportsTrivyFailure(t *testing.T) {
	r := Runner{Bin: "trivy", exec: (&fakeExec{err: errors.New("exit status 1: no such image")}).run}
	_, err := r.Scan(context.Background(), "missing:latest")
	if err == nil || !strings.Contains(err.Error(), "no such image") {
		t.Fatalf("expected the trivy error to be surfaced, got %v", err)
	}
}

func TestRunnerRejectsEmptyImage(t *testing.T) {
	r := NewRunner("trivy", time.Minute)
	if _, err := r.Scan(context.Background(), "  "); err == nil {
		t.Fatal("expected an error for an empty image reference")
	}
}

func TestRunnerRejectsOptionLookingImage(t *testing.T) {
	r := NewRunner("trivy", time.Minute)
	if _, err := r.Scan(context.Background(), "--config=/etc/passwd"); err == nil {
		t.Fatal("an image reference must not be passed through as a trivy flag")
	}
}

func TestRunnerKeepsScanWhenVersionLookupFails(t *testing.T) {
	calls := 0
	exec := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls++
		if args[0] == "version" {
			return nil, errors.New("boom")
		}
		return readFixture(t, "trivy-alpine-3.18.0.json"), nil
	}
	res, err := Runner{Bin: "trivy", exec: exec}.Scan(context.Background(), "alpine:3.18.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanner.DBUpdatedAt != nil {
		t.Error("database time should be empty when `trivy version` fails")
	}
}

func TestDefaultExecIncludesStderrInErrors(t *testing.T) {
	_, err := defaultExec(context.Background(), "sh", "-c", "echo bad thing >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "bad thing") {
		t.Fatalf("expected stderr in the error, got %v", err)
	}
}

func TestDefaultExecReturnsStdout(t *testing.T) {
	out, err := defaultExec(context.Background(), "sh", "-c", "printf hello")
	if err != nil || string(out) != "hello" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestRunnerIgnoresRepositoryTrivySettings(t *testing.T) {
	fake := &fakeExec{outputs: map[string][]byte{
		"image":   readFixture(t, "trivy-alpine-3.18.0.json"),
		"version": readFixture(t, "trivy-version.json"),
	}}
	r := Runner{Bin: "trivy", Timeout: 30 * time.Minute, exec: fake.run}
	if _, err := r.Scan(context.Background(), "alpine:3.18.0"); err != nil {
		t.Fatal(err)
	}
	scan := strings.Join(fake.calls[0], " ")
	for _, want := range []string{
		"--config " + os.DevNull,
		"--ignorefile  ",
		"--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--ignore-unfixed=false",
		"--timeout 30m0s",
	} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan command %q is missing %q", scan, want)
		}
	}
}

func TestSafeEnvironDropsTrivySettings(t *testing.T) {
	got := safeEnviron([]string{
		"PATH=/bin", "AWS_REGION=us-east-2",
		"TRIVY_USERNAME=AWS", "TRIVY_PASSWORD=x", "TRIVY_CACHE_DIR=/c", "TRIVY_DB_REPOSITORY=mirror",
		"TRIVY_IGNORE_UNFIXED=true", "TRIVY_SEVERITY=LOW", "TRIVY_IGNOREFILE=a", "TRIVY_VEX=repo", "TRIVY_SKIP_FILES=x",
	})
	joined := strings.Join(got, " ")
	for _, keep := range []string{"PATH=/bin", "AWS_REGION", "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_CACHE_DIR", "TRIVY_DB_REPOSITORY"} {
		if !strings.Contains(joined, keep) {
			t.Errorf("%s should be kept", keep)
		}
	}
	for _, drop := range []string{"TRIVY_IGNORE_UNFIXED", "TRIVY_SEVERITY", "TRIVY_IGNOREFILE", "TRIVY_VEX", "TRIVY_SKIP_FILES"} {
		if strings.Contains(joined, drop) {
			t.Errorf("%s can hide findings and must be removed", drop)
		}
	}
}

func TestDefaultExecDoesNotPassTrivySettings(t *testing.T) {
	t.Setenv("TRIVY_SEVERITY", "LOW")
	out, err := defaultExec(context.Background(), "sh", "-c", "printf %s \"$TRIVY_SEVERITY\"")
	if err != nil || string(out) != "" {
		t.Fatalf("TRIVY_SEVERITY leaked into the child process: %q %v", out, err)
	}
}
