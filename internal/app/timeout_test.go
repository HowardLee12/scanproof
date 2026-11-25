package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sleepyTool is a fake tool that answers --version and otherwise runs body.
func sleepyTool(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tool")
	writeFile(t, bin, "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'ClamAV 1.4.7/28193/Tue Nov 24 06:27:44 2026'; exit 0; fi\n"+body+"\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestScanDirReportsTheTimeoutDuringTheMalwareScan(t *testing.T) {
	h := newHarness()
	h.noGrace()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--sbom=false", "--malware", "--clamscan", sleepyTool(t, "sleep 10"), "--timeout", "500ms", makeSoftwareDir(t))
	want := "scanproof: the scan stopped at its --timeout of 500ms during the malware scan (0 of 3 files scanned); raise --timeout\n"
	if code != ExitError || !strings.HasSuffix(h.stderr.String(), want) {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
	for _, wrong := range []string{"exited with", "-1", "example-worker", "eicar"} {
		if strings.Contains(h.stderr.String(), wrong) {
			t.Errorf("the message must not mention %q: %q", wrong, h.stderr.String())
		}
	}
}

func TestScanReportsTheTimeoutDuringTrivy(t *testing.T) {
	h := newHarness()
	h.noGrace()
	bin := trivyScript(t, `if [ "$1" = rootfs ] || [ "$1" = image ]; then sleep 10; fi`)
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", bin, "--out", t.TempDir(), "--pdf=false",
		"--timeout", "500ms", makeSoftwareDir(t))
	want := "the scan stopped at its --timeout of 500ms during the Trivy scan; raise --timeout"
	if code != ExitError || !strings.Contains(h.stderr.String(), want) {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestAClamscanKilledBeforeTheDeadlineIsReportedAsSuch(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--sbom=false", "--malware", "--clamscan", sleepyTool(t, "kill -9 $$"), makeSoftwareDir(t))
	stderr := h.stderr.String()
	if code != ExitError || !strings.Contains(stderr, "while scanning batch 1 (files 1–3 of 3 in path order): clamscan was killed by signal: killed") ||
		strings.Contains(stderr, "--timeout") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestFreshclamCutOffByTheTimeoutStopsTheScan(t *testing.T) {
	h := newHarness()
	h.noGrace()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--sbom=false", "--malware", "--clamscan", fakeClamscan(t), "--clamav-update", "--freshclam", sleepyTool(t, "sleep 10"),
		"--timeout", "500ms", makeSoftwareDir(t))
	if code != ExitError || !strings.Contains(h.stderr.String(), "during the ClamAV signature update") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestScanDirPrintsMalwareProgress(t *testing.T) {
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", t.TempDir(), "--pdf=false",
		"--sbom=false", "--malware", "--clamscan", fakeClamscan(t), makeSoftwareDir(t))
	if code != 0 || !strings.Contains(h.stderr.String(), "scanproof: malware scan: 3 of 3 files scanned (100%), batch 1, ") {
		t.Fatalf("code %d, stderr %q", code, h.stderr.String())
	}
}

func TestRescanTimeoutNamesTheImage(t *testing.T) {
	storeDir := t.TempDir()
	digest := seedDirectoryScan(t, storeDir, fakeTrivy(t), makeSoftwareDir(t))
	images := filepath.Join(t.TempDir(), "images.txt")
	writeFile(t, images, "dir:acme-vllm:0.9.1@"+digest+"\n")
	h := newHarness()
	h.noGrace()
	received := notifyServer(t, h)
	start := time.Now()
	code := h.run("rescan", "--store", "file://"+storeDir, "--inventory", "file", "--images-file", images,
		"--trivy", trivyScript(t, `if [ "$1" = sbom ]; then sleep 10; fi`), "--out", t.TempDir(), "--timeout", "500ms")
	want := "scanproof: directory acme-vllm:0.9.1: the rescan of this directory stopped at its --timeout of 500ms during the Trivy SBOM scan; raise --timeout"
	if code != ExitError || !strings.Contains(h.stderr.String(), want) || time.Since(start) > 8*time.Second {
		t.Fatalf("code %d after %s, stderr %q", code, time.Since(start), h.stderr.String())
	}
	if body := string(next(t, received)); !strings.Contains(body, "stopped at its --timeout of 500ms during the Trivy SBOM scan") {
		t.Errorf("the chat message must say why: %s", body)
	}
}
