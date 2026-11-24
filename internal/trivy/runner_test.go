package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

	scan, err := r.Scan(context.Background(), "alpine:3.18.0")
	if err != nil {
		t.Fatal(err)
	}
	res := scan.Result
	if len(scan.Raw) == 0 {
		t.Error("the raw Trivy report is needed to build the SBOM")
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 trivy calls, got %d", len(fake.calls))
	}
	cmd := strings.Join(fake.calls[0], " ")
	for _, want := range []string{"/usr/bin/trivy image", "--format json", "--scanners vuln,secret", "--list-all-pkgs", "alpine:3.18.0"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("scan command %q is missing %q", cmd, want)
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
	scan, err := Runner{Bin: "trivy", exec: exec}.Scan(context.Background(), "alpine:3.18.0")
	if err != nil {
		t.Fatal(err)
	}
	if scan.Result.Scanner.DBUpdatedAt != nil {
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

func TestSBOMConvertsTheRawReport(t *testing.T) {
	var gotArgs []string
	var gotInput []byte
	exec := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		in, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		gotInput = in
		out := args[indexOf(args, "--output")+1]
		return nil, os.WriteFile(out, []byte(`{"bomFormat":"CycloneDX"}`), 0o600)
	}
	sbom, err := Runner{Bin: "trivy", exec: exec}.SBOM(context.Background(), []byte(`{"SchemaVersion":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(sbom) != `{"bomFormat":"CycloneDX"}` || string(gotInput) != `{"SchemaVersion":2}` {
		t.Fatalf("sbom %s, input %s", sbom, gotInput)
	}
	if gotArgs[0] != "convert" || !strings.Contains(strings.Join(gotArgs, " "), "--format cyclonedx") {
		t.Errorf("args = %v", gotArgs)
	}
	if dir := filepath.Dir(gotArgs[len(gotArgs)-1]); dirExists(dir) {
		t.Error("the temporary directory should be removed")
	}
}

func TestSBOMReportsFailure(t *testing.T) {
	exec := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("convert failed") }
	if _, err := (Runner{Bin: "trivy", exec: exec}).SBOM(context.Background(), []byte("{}")); err == nil {
		t.Fatal("expected an error")
	}
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func TestScanSBOMUsesTheSameHardenedFlags(t *testing.T) {
	var args []string
	var input []byte
	exec := func(_ context.Context, _ string, a ...string) ([]byte, error) {
		if a[0] == "version" {
			return readFixture(t, "trivy-version.json"), nil
		}
		args = a
		data, err := os.ReadFile(a[len(a)-1])
		input = data
		if err != nil {
			return nil, err
		}
		return readFixture(t, "trivy-alpine-3.18.0.json"), nil
	}
	scan, err := Runner{Bin: "trivy", Timeout: time.Minute, exec: exec}.ScanSBOM(context.Background(), []byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil {
		t.Fatal(err)
	}
	cmd := strings.Join(args, " ")
	for _, want := range []string{"sbom ", "--scanners vuln", "--config " + os.DevNull, "--ignorefile  ", "--ignore-unfixed=false", "--timeout 1m0s"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command %q is missing %q", cmd, want)
		}
	}
	if string(input) != `{"bomFormat":"CycloneDX"}` {
		t.Errorf("trivy should read the SBOM, got %s", input)
	}
	if len(scan.Result.Vulnerabilities) != 49 || scan.Result.Scanner.DBUpdatedAt == nil {
		t.Errorf("unexpected result: %d vulns", len(scan.Result.Vulnerabilities))
	}
}

func TestScanSBOMReportsFailure(t *testing.T) {
	exec := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("bad sbom") }
	if _, err := (Runner{Bin: "trivy", exec: exec}).ScanSBOM(context.Background(), []byte("{}")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunnerPassesPlatform(t *testing.T) {
	fake := &fakeExec{outputs: map[string][]byte{"image": readFixture(t, "trivy-alpine-3.18.0.json")}}
	if _, err := (Runner{Bin: "trivy", Platform: "linux/arm64", exec: fake.run}).Scan(context.Background(), "alpine:3.18.0"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(fake.calls[0], " "), "--platform linux/arm64 alpine:3.18.0") {
		t.Errorf("command = %v", fake.calls[0])
	}
}

func TestScanRootfsUsesRootfsModeAndTheSameHardening(t *testing.T) {
	fake := &fakeExec{outputs: map[string][]byte{
		"rootfs":  readFixture(t, "trivy-alpine-3.18.0.json"),
		"version": readFixture(t, "trivy-version.json"),
	}}
	r := Runner{Bin: "trivy", Timeout: time.Minute, Platform: "linux/arm64", exec: fake.run}
	scan, err := r.ScanRootfs(context.Background(), "/mnt/shared/venv")
	if err != nil {
		t.Fatal(err)
	}
	cmd := strings.Join(fake.calls[0], " ")
	for _, want := range []string{
		"trivy rootfs", "--format json", "--scanners vuln,secret", "--list-all-pkgs",
		"--config " + os.DevNull, "--ignorefile  ", "--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--ignore-unfixed=false", "--timeout 1m0s",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command %q is missing %q", cmd, want)
		}
	}
	if !strings.HasSuffix(cmd, " /mnt/shared/venv") || strings.Contains(cmd, "--platform") {
		t.Errorf("the path must come last and --platform only applies to images: %q", cmd)
	}
	if len(scan.Raw) == 0 || scan.Result.Scanner.DBUpdatedAt == nil {
		t.Error("the raw report (for the SBOM) and the database time are needed")
	}
}

func TestScanRootfsRejectsBadPaths(t *testing.T) {
	r := NewRunner("trivy", time.Minute)
	for _, p := range []string{"", "  ", "--config=/etc/passwd", "relative/path"} {
		if _, err := r.ScanRootfs(context.Background(), p); err == nil {
			t.Errorf("%q must be rejected", p)
		}
	}
}

func TestScanRootfsReportsFailure(t *testing.T) {
	r := Runner{Bin: "trivy", exec: (&fakeExec{err: errors.New("exit status 1: permission denied")}).run}
	if _, err := r.ScanRootfs(context.Background(), "/srv/app"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("got %v", err)
	}
}

// scanFuncs runs an image, rootfs and SBOM scan with a fake Trivy that
// passes the arguments of each scan to check.
func scanFuncs(t *testing.T, check func(bin string, args []string)) []func() {
	t.Helper()
	exec := func(_ context.Context, bin string, args ...string) ([]byte, error) {
		if args[0] == "version" {
			return readFixture(t, "trivy-version.json"), nil
		}
		check(bin, args)
		return readFixture(t, "trivy-alpine-3.18.0.json"), nil
	}
	r := Runner{Bin: "trivy", exec: exec}
	return []func(){
		func() { mustScan(t)(r.Scan(context.Background(), "alpine:3.18.0")) },
		func() { mustScan(t)(r.ScanRootfs(context.Background(), "/srv/app")) },
		func() { mustScan(t)(r.ScanSBOM(context.Background(), []byte("{}"))) },
	}
}

func mustScan(t *testing.T) func(Scan, error) {
	return func(_ Scan, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
}
