package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanDirSBOMFailureWritesNoEvidence(t *testing.T) {
	out := t.TempDir()
	summary := filepath.Join(t.TempDir(), "step-summary.md")
	bin := trivyScript(t, `if [ "$1" = convert ]; then echo "convert broke" >&2; exit 1; fi`)
	h := newHarness()
	h.env["GITHUB_ACTIONS"] = "true"
	h.env["GITHUB_STEP_SUMMARY"] = summary
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", bin, "--out", out, "--pdf=false",
		"--store", "file://"+t.TempDir(), makeSoftwareDir(t))
	if code != ExitError {
		t.Fatalf("code %d", code)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("no evidence may be written for a failed scan: %v", entries)
	}
	if _, err := os.Stat(summary); err == nil {
		t.Error("the job summary must not be written for a failed scan")
	}
}

func TestStepSummaryIsNotWrittenWhenTheUploadFails(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	writeFile(t, notADir, "x")
	summary := filepath.Join(t.TempDir(), "step-summary.md")
	h := newHarness()
	h.env["GITHUB_ACTIONS"] = "true"
	h.env["GITHUB_STEP_SUMMARY"] = summary
	code := h.run("scan", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false", "--sbom=false",
		"--store", "file://"+filepath.Join(notADir, "store"), "--", "alpine:3.18.0")
	if code != ExitError {
		t.Fatalf("code %d", code)
	}
	if _, err := os.Stat(summary); err == nil {
		t.Error("the job summary must not be written for a failed scan")
	}
}

func TestScanDirDetectsARootSwappedWhileTrivyRuns(t *testing.T) {
	root := filepath.Join(t.TempDir(), "venv")
	if err := os.Rename(makeSoftwareDir(t), root); err != nil {
		t.Fatal(err)
	}
	// While "scanning", move the directory away, scan a decoy, and put it back.
	bin := trivyScript(t, `if [ "$1" = rootfs ]; then sleep 0.05; mv "$last" "$last.real"; mkdir "$last"; `+
		`rmdir "$last"; mv "$last.real" "$last"; fi`)
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", bin, "--out", t.TempDir(), "--pdf=false", root)
	if code != ExitError || !strings.Contains(h.stderr.String(), "the directory itself changed while it was being scanned") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestOutputInsideTheRootIsFoundWhateverTheCase(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("only case-insensitive file systems")
	}
	root := makeSoftwareDir(t)
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--pdf=false",
		"--out", strings.ToUpper(root)+"/evidence", root)
	if code != ExitError || !strings.Contains(h.stderr.String(), "inside the scanned directory") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}
