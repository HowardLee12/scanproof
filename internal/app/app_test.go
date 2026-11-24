package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixture = "../../testdata/trivy-alpine-3.18.0.json"

type harness struct {
	env    map[string]string
	stdout bytes.Buffer
	stderr bytes.Buffer
	client *http.Client
	now    time.Time
}

func newHarness() *harness {
	return &harness{env: map[string]string{}}
}

func (h *harness) run(args ...string) int {
	return Run(context.Background(), args, Env{
		Getenv: func(k string) string { return h.env[k] },
		Stdout: &h.stdout,
		Stderr: &h.stderr,
		Now: func() time.Time {
			if !h.now.IsZero() {
				return h.now
			}
			return time.Date(2026, 11, 24, 8, 16, 48, 0, time.UTC)
		},
		HTTPClient: h.client,
	})
}

func TestVersion(t *testing.T) {
	h := newHarness()
	if code := h.run("version"); code != 0 || !strings.Contains(h.stdout.String(), "scanproof") {
		t.Fatalf("code %d, output %q", code, h.stdout.String())
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"scan"}, {"scan", "a", "b"}, {"scan", "--mode", "strict", "img"},
		{"scan", "--timeout", "0s", "img"}} {
		h := newHarness()
		if code := h.run(args...); code != ExitError {
			t.Errorf("%v: code %d, want %d", args, code, ExitError)
		}
	}
}

func TestHelp(t *testing.T) {
	h := newHarness()
	if code := h.run("help"); code != 0 || !strings.Contains(h.stdout.String(), "scanproof scan") {
		t.Fatalf("code %d, output %q", code, h.stdout.String())
	}
}

func TestScanFromResultsFileWritesEvidence(t *testing.T) {
	out := t.TempDir()
	h := newHarness()
	summary := filepath.Join(t.TempDir(), "step-summary.md")
	outputs := filepath.Join(t.TempDir(), "outputs.txt")
	h.env["GITHUB_ACTIONS"] = "true"
	h.env["GITHUB_STEP_SUMMARY"] = summary
	h.env["GITHUB_OUTPUT"] = outputs
	h.env["GITHUB_REPOSITORY"] = "example-org/example-api"

	code := h.run("scan", "--trivy-results", fixture, "--out", out, "--pdf=false")
	if code != 0 {
		t.Fatalf("warn mode must exit 0, got %d: %s", code, h.stderr.String())
	}
	for _, name := range []string{"results.json", "summary.md", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "report.pdf")); err == nil {
		t.Error("report.pdf must not be written with --pdf=false")
	}

	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	if doc["verdict"] != "WARN" || doc["report_id"] == "" {
		t.Errorf("unexpected results.json header: %v %v", doc["verdict"], doc["report_id"])
	}
	var manifest struct {
		Files []struct{ Name string } `json:"files"`
	}
	readJSON(t, filepath.Join(out, "manifest.json"), &manifest)
	if len(manifest.Files) != 2 {
		t.Errorf("manifest should hash results.json and summary.md: %+v", manifest.Files)
	}

	if s := readFile(t, summary); !strings.Contains(s, "ScanProof: WARN") {
		t.Errorf("step summary not appended: %q", s)
	}
	if o := readFile(t, outputs); !strings.Contains(o, "verdict=WARN") || !strings.Contains(o, "violations=3") {
		t.Errorf("step outputs = %q", o)
	}
	if !strings.Contains(h.stdout.String(), "::warning title=ScanProof::") {
		t.Errorf("expected a GitHub warning annotation, got %q", h.stdout.String())
	}
}

func TestEnforceModeFails(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--trivy-results", fixture, "--out", t.TempDir(), "--pdf=false", "--mode", "enforce")
	if code != ExitViolation {
		t.Fatalf("code %d, want %d", code, ExitViolation)
	}
}

func TestPolicyFileAndExceptions(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	excs := filepath.Join(dir, "exceptions.yaml")
	writeFile(t, pol, "mode: enforce\n")
	writeFile(t, excs, `exceptions:
  - {id: EX-1, finding: CVE-2022-48174, reason: r, expires: 2027-01-31}
`)
	h := newHarness()
	code := h.run("scan", "--trivy-results", fixture, "--out", dir, "--pdf=false", "--policy", pol, "--exceptions", excs)
	if code != 0 {
		t.Fatalf("all fixable Criticals are accepted, so enforce mode should pass; code %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "PASS") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
}

func TestBadPolicyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	writeFile(t, pol, "mode: strict\n")
	h := newHarness()
	if code := h.run("scan", "--trivy-results", fixture, "--out", dir, "--policy", pol); code != ExitError {
		t.Fatalf("code %d", code)
	}
	if code := newHarness().run("scan", "--trivy-results", fixture, "--out", dir, "--exceptions", "/nope.yaml"); code != ExitError {
		t.Fatalf("missing exceptions file: code %d", code)
	}
	if code := newHarness().run("scan", "--trivy-results", "/nope.json", "--out", dir); code != ExitError {
		t.Fatalf("missing results file: code %d", code)
	}
}

func TestMissingTypstOnlyWarns(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--trivy-results", fixture, "--out", t.TempDir(), "--typst", "no-such-typst-binary")
	if code != 0 || !strings.Contains(h.stderr.String(), "skipping report.pdf") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestRunsTrivyBinary(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "trivy")
	abs, _ := filepath.Abs(fixture)
	writeFile(t, fake, "#!/bin/sh\nif [ \"$1\" = version ]; then echo '{\"Version\":\"0.76.2\"}'; else cat '"+abs+"'; fi\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	h := newHarness()
	code := h.run("scan", "--trivy", fake, "--out", filepath.Join(dir, "out"), "--pdf=false", "alpine:3.18.0")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
}

func TestNotifiesConfiguredWebhook(t *testing.T) {
	received := make(chan []byte, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := newHarness()
	h.client = srv.Client()
	h.env["SCANPROOF_DISCORD_WEBHOOK_URL"] = srv.URL + "/api/webhooks/1/token"
	if code := h.run("scan", "--trivy-results", fixture, "--out", t.TempDir(), "--pdf=false"); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	select {
	case body := <-received:
		if !strings.Contains(string(body), "ScanProof WARN") {
			t.Errorf("unexpected payload %s", body)
		}
	default:
		t.Fatal("no notification was sent")
	}
}

func TestNotificationFailureOnlyWarns(t *testing.T) {
	h := newHarness()
	h.env["SCANPROOF_SLACK_WEBHOOK_URL"] = "http://insecure.example/hook"
	code := h.run("scan", "--trivy-results", fixture, "--out", t.TempDir(), "--pdf=false")
	if code != 0 || !strings.Contains(h.stderr.String(), "notification") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestEscapeAnnotation(t *testing.T) {
	if got := escapeAnnotation("a%b\nc"); got != "a%25b%0Ac" {
		t.Fatalf("got %q", got)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(readFile(t, path)), v); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStalePDFIsRemoved(t *testing.T) {
	out := t.TempDir()
	stale := filepath.Join(out, "report.pdf")
	writeFile(t, stale, "%PDF- from an earlier run")
	h := newHarness()
	if code := h.run("scan", "--trivy-results", fixture, "--out", out, "--pdf=false"); code != 0 {
		t.Fatalf("code %d", code)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("a PDF from an earlier run must not be left next to new results")
	}
}

func TestImportedResultsMustBeContainerImage(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--trivy-results", "../../testdata/trivy-secrets.json", "--out", t.TempDir(), "--pdf=false")
	if code != ExitError || !strings.Contains(h.stderr.String(), "container_image") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestImportedResultsAreLabelled(t *testing.T) {
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--trivy-results", fixture, "--out", out, "--pdf=false"); code != 0 {
		t.Fatalf("code %d", code)
	}
	if s := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(s, "secret scanning not verified") {
		t.Errorf("imported results should be labelled: %q", s)
	}
}

func TestDoubleDashEndsFlags(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "trivy")
	abs, _ := filepath.Abs(fixture)
	writeFile(t, fake, "#!/bin/sh\nif [ \"$1\" = version ]; then echo '{}'; else cat '"+abs+"'; fi\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	h := newHarness()
	if code := h.run("scan", "--trivy", fake, "--out", filepath.Join(dir, "out"), "--pdf=false", "--", "alpine:3.18.0"); code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	h = newHarness()
	if code := h.run("scan", "--trivy", fake, "--out", filepath.Join(dir, "out"), "--", "--trivy-results=x.json"); code != ExitError {
		t.Fatalf("a dash-leading image after -- must be rejected, got %d", code)
	}
}

// fakeTrivy writes a script that answers `version`, `convert` and `image`.
func fakeTrivy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trivy")
	abs, _ := filepath.Abs(fixture)
	script := `#!/bin/sh
case "$1" in
  version) echo '{"Version":"0.76.2"}' ;;
  convert)
    out=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "--output" ]; then out="$2"; fi
      shift
    done
    echo '{"bomFormat":"CycloneDX"}' > "$out" ;;
  *) cat '` + abs + `' ;;
esac
`
	writeFile(t, path, script)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanStoresEvidenceAndSBOM(t *testing.T) {
	storeDir := t.TempDir()
	outputs := filepath.Join(t.TempDir(), "outputs.txt")
	h := newHarness()
	h.env["GITHUB_ACTIONS"] = "true"
	h.env["GITHUB_OUTPUT"] = outputs
	code := h.run("scan", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--store", "file://"+storeDir, "--", "alpine:3.18.0")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}

	days, err := filepath.Glob(filepath.Join(storeDir, "scans", "2026", "11", "24", "SR-*"))
	if err != nil || len(days) != 1 {
		t.Fatalf("expected one stored scan, got %v %v", days, err)
	}
	for _, name := range []string{"results.json", "summary.md", "sbom.cdx.json", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(days[0], name)); err != nil {
			t.Errorf("%s not stored: %v", name, err)
		}
	}
	var doc map[string]any
	readJSON(t, filepath.Join(days[0], "results.json"), &doc)
	if doc["trigger"] != "ci" {
		t.Errorf("trigger = %v", doc["trigger"])
	}
	if o := readFile(t, outputs); !strings.Contains(o, "evidence-url=file://") {
		t.Errorf("outputs = %q", o)
	}
}

func TestManualScanTrigger(t *testing.T) {
	out := t.TempDir()
	h := newHarness()
	if code := h.run("scan", "--trivy-results", fixture, "--out", out, "--pdf=false", "--sbom=false"); code != 0 {
		t.Fatalf("code %d", code)
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	if doc["trigger"] != "manual" {
		t.Errorf("trigger = %v", doc["trigger"])
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); err == nil {
		t.Error("--sbom=false must not write an SBOM")
	}
}

func TestInvalidStoreFailsBeforeScanning(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--trivy-results", fixture, "--out", t.TempDir(), "--store", "ftp://nowhere/x")
	if code != ExitError || !strings.Contains(h.stderr.String(), "unsupported store URL") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestStoreWriteFailureIsAnError(t *testing.T) {
	// The store path is below a regular file, so every write fails, even
	// for root, which ignores directory permissions.
	notADir := filepath.Join(t.TempDir(), "file")
	writeFile(t, notADir, "x")
	h := newHarness()
	code := h.run("scan", "--trivy", fakeTrivy(t), "--pdf=false", "--sbom=false", "--store", "file://"+filepath.Join(notADir, "store"),
		"--out", t.TempDir(), "--", "alpine:3.18.0")
	if code != ExitError {
		t.Fatalf("an evidence upload failure must fail the step, got %d", code)
	}
}
