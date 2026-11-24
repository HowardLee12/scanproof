package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedStore stores scans on several November days.
func seedStore(t *testing.T) string {
	t.Helper()
	storeDir := t.TempDir()
	trivyBin := fakeTrivy(t)
	for _, d := range []int{3, 10, 24} {
		h := newHarness()
		h.now = time.Date(2026, 11, d, 6, 0, 0, 0, time.UTC)
		code := h.run("scan", "--trivy", trivyBin, "--out", t.TempDir(), "--pdf=false", "--sbom=false",
			"--store", "file://"+storeDir, "--", "alpine:3.18.0")
		if code != 0 {
			t.Fatalf("seed scan on day %d: %d %s", d, code, h.stderr.String())
		}
	}
	return storeDir
}

func TestReportWritesPeriodSummary(t *testing.T) {
	storeDir := seedStore(t)
	out := t.TempDir()
	h := newHarness()
	h.now = time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)
	code := h.run("report", "--store", "file://"+storeDir, "--from", "2026-11-01", "--to", "2026-11-30",
		"--out", out, "--pdf=false")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	for _, name := range []string{"summary.json", "population.csv", "summary.md", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	csv := readFile(t, filepath.Join(out, "population.csv"))
	if lines := strings.Count(csv, "\n"); lines != 4 {
		t.Errorf("population should have a header and 3 scans, got %d lines:\n%s", lines, csv)
	}
	var s map[string]any
	readJSON(t, filepath.Join(out, "summary.json"), &s)
	if s["population_count"] != float64(3) {
		t.Errorf("population_count = %v", s["population_count"])
	}
	if !strings.Contains(h.stdout.String(), "3 scans") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
}

func TestReportSaveToStore(t *testing.T) {
	storeDir := seedStore(t)
	h := newHarness()
	h.now = time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)
	code := h.run("report", "--store", "file://"+storeDir, "--from", "2026-11-01", "--to", "2026-11-30",
		"--out", t.TempDir(), "--pdf=false", "--save")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	saved, _ := filepath.Glob(filepath.Join(storeDir, "summaries", "2026-11-01_2026-11-30", "PS-*", "summary.json"))
	if len(saved) != 1 {
		t.Fatalf("summary not saved to the store: %v", saved)
	}
}

func TestReportUsageErrors(t *testing.T) {
	cases := [][]string{
		{"report", "--from", "2026-11-01", "--to", "2026-11-30"},
		{"report", "--store", "file:///tmp/x", "--to", "2026-11-30"},
		{"report", "--store", "file:///tmp/x", "--from", "2026-11-30", "--to", "2026-11-01"},
		{"report", "--store", "file:///tmp/x", "--from", "Nov 1", "--to", "2026-11-30"},
		{"report", "--store", "file:///tmp/x", "--from", "2026-11-01", "--to", "2026-11-30", "--lookback-days", "-1"},
		{"report", "--store", "ftp://x", "--from", "2026-11-01", "--to", "2026-11-30"},
	}
	for _, args := range cases {
		h := newHarness()
		if code := h.run(args...); code != ExitError {
			t.Errorf("%v: code %d, want %d", args, code, ExitError)
		}
	}
}
