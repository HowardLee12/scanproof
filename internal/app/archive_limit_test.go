package app

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMalwareMaxArchiveFilesFlag(t *testing.T) {
	dir := t.TempDir()
	opts, err := parseScanOptions([]string{"--dir", "--name", "acme-vllm", "--malware", dir}, io.Discard)
	if err != nil || opts.Malware.MaxArchiveFiles != 10000 {
		t.Fatalf("default: %d, %v; want ClamAV's own default of 10000", opts.Malware.MaxArchiveFiles, err)
	}
	opts, err = parseScanOptions([]string{"--malware-max-archive-files", "50000", "--malware", "example-api:1.0"}, io.Discard)
	if err != nil || opts.Malware.MaxArchiveFiles != 50000 {
		t.Fatalf("raised: %d, %v", opts.Malware.MaxArchiveFiles, err)
	}
}

func TestMalwareMaxArchiveFilesMustBeSane(t *testing.T) {
	cases := map[string]string{
		"0":       "--malware-max-archive-files must be between 1 and 1,000,000, got 0",
		"-5":      "--malware-max-archive-files must be between 1 and 1,000,000, got -5",
		"1000001": "--malware-max-archive-files must be between 1 and 1,000,000, got 1000001",
		"lots":    `invalid value "lots" for flag -malware-max-archive-files`,
		"1e5":     `invalid value "1e5" for flag -malware-max-archive-files`,
	}
	for value, want := range cases {
		var stderr strings.Builder
		_, err := parseScanOptions([]string{"--malware", "--malware-max-archive-files", value, "example-api:1.0"}, &stderr)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", value, err, want)
		}
	}
	if _, err := parseScanOptions([]string{"--malware-max-archive-files", "1000000", "x:1"}, io.Discard); err != nil {
		t.Errorf("the upper bound itself is allowed: %v", err)
	}
	if _, err := parseScanOptions([]string{"--malware-max-file-mb", "0", "x:1"}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "--malware-max-file-mb must be between 1 and 4000") {
		t.Errorf("the file size limit is still checked: %v", err)
	}
}

// argsClamscan is fakeClamscan that also appends its arguments to a log.
func argsClamscan(t *testing.T) (bin, log string) {
	t.Helper()
	inner := fakeClamscan(t)
	log = filepath.Join(t.TempDir(), "args.log")
	bin = filepath.Join(t.TempDir(), "clamscan")
	writeFile(t, bin, "#!/bin/sh\necho \"$@\" >> '"+log+"'\nexec '"+inner+"' \"$@\"\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

func TestScanDirPassesAndRecordsTheArchiveLimit(t *testing.T) {
	clamscan, log := argsClamscan(t)
	out := t.TempDir()
	h := newHarness()
	code := h.run("scan", "--dir", "--name", "acme-vllm", "--trivy", fakeTrivy(t), "--out", out, "--pdf=false",
		"--sbom=false", "--malware", "--clamscan", clamscan, "--malware-max-archive-files", "50000",
		"--malware-workdir", t.TempDir(), makeSoftwareDir(t))
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	if args := readFile(t, log); !strings.Contains(args, "--max-files=50000") || !strings.Contains(args, "--max-scansize=2048M") ||
		!strings.Contains(args, "--max-scantime=600000") {
		t.Errorf("clamscan args: %s", args)
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	limits, _ := doc["malware"].(map[string]any)["limits"].(map[string]any)
	if limits["max_archive_files"] != float64(50000) || limits["max_file_bytes"] != float64(512<<20) ||
		limits["max_scan_bytes"] != float64(2048<<20) || limits["max_scan_time_ms"] != float64(600000) {
		t.Fatalf("limits = %v", limits)
	}
	if md := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(md, "at most 50,000 files") {
		t.Errorf("the job summary should show the limits:\n%s", md)
	}
}

func TestImageScanStatesClamAVsDefaultArchiveLimit(t *testing.T) {
	clamscan, log := argsClamscan(t)
	ref, config := pushImage(t, map[string][]byte{"app/main": []byte("binary")})
	out := t.TempDir()
	h := newHarness()
	code := h.run("scan", "--trivy", fakeTrivyFor(t, config), "--out", out, "--pdf=false", "--sbom=false",
		"--malware", "--clamscan", clamscan, "--docker-daemon=false", "--", ref)
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	if args := readFile(t, log); !strings.Contains(args, "--max-files=10000") {
		t.Errorf("clamscan args: %s", args)
	}
	var doc map[string]any
	readJSON(t, filepath.Join(out, "results.json"), &doc)
	if limits, _ := doc["malware"].(map[string]any)["limits"].(map[string]any); limits["max_archive_files"] != float64(10000) {
		t.Fatalf("limits = %v", limits)
	}
}
