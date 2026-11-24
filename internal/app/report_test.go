package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/report"
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
	for _, name := range []string{"summary.json", "population.csv", "findings.csv", "summary.md", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	checkFindingsCSV(t, out)
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
	stored := filepath.Dir(saved[0])
	for _, name := range []string{"population.csv", "findings.csv", "summary.md", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(stored, name)); err != nil {
			t.Errorf("%s not saved to the store: %v", name, err)
		}
	}
}

// checkFindingsCSV checks that findings.csv has one row per tracked finding
// and that the summary's manifest hashes it.
func checkFindingsCSV(t *testing.T, out string) {
	t.Helper()
	var s map[string]any
	readJSON(t, filepath.Join(out, "summary.json"), &s)
	count, _ := s["findings_count"].(float64)
	csv := readFile(t, filepath.Join(out, "findings.csv"))
	if count == 0 || strings.Count(csv, "\n") != int(count)+1 {
		t.Errorf("findings.csv should have a header and %v findings:\n%s", s["findings_count"], csv)
	}
	if !strings.HasPrefix(csv, "image,artifact_type,id,package,severity,") || !strings.Contains(csv, ",open_in_sla,") {
		t.Errorf("findings.csv = %s", csv)
	}
	var manifest report.Manifest
	readJSON(t, filepath.Join(out, "manifest.json"), &manifest)
	sum, _, err := report.HashFile(filepath.Join(out, "findings.csv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range manifest.Files {
		if f.Name == "findings.csv" && f.SHA256 == sum {
			return
		}
	}
	t.Errorf("manifest.json does not hash findings.csv: %+v", manifest.Files)
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

// fakeTypst writes a stand-in PDF and keeps a copy of the data it was given.
func fakeTypst(t *testing.T) (bin, data string) {
	t.Helper()
	dir := t.TempDir()
	bin, data = filepath.Join(dir, "typst"), filepath.Join(dir, "data.json")
	writeFile(t, bin, `#!/bin/sh
for last; do :; done
while [ $# -gt 0 ]; do
  if [ "$1" = "--root" ]; then cp "$2/data.json" '`+data+`'; fi
  shift
done
printf '%%PDF-1.7 fake' > "$last"
`)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, data
}

func TestReportPDFPrintsTheFindingsHash(t *testing.T) {
	storeDir := seedStore(t)
	out := t.TempDir()
	typst, data := fakeTypst(t)
	h := newHarness()
	h.now = time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)
	code := h.run("report", "--store", "file://"+storeDir, "--from", "2026-11-01", "--to", "2026-11-30",
		"--out", out, "--typst", typst, "--save")
	if code != 0 {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	sum, _, err := report.HashFile(filepath.Join(out, "findings.csv"))
	if err != nil {
		t.Fatal(err)
	}
	view := readFile(t, data)
	if !strings.Contains(view, `"findings.csv SHA-256"`) || !strings.Contains(view, sum) || !strings.Contains(view, `"findings_count"`) {
		t.Errorf("the PDF must print the findings.csv hash and count: %s", view)
	}
	saved, _ := filepath.Glob(filepath.Join(storeDir, "summaries", "*", "PS-*", "summary.pdf"))
	if len(saved) != 1 {
		t.Errorf("summary.pdf not saved: %v", saved)
	}
}

func TestReportWithoutTypstSkipsThePDF(t *testing.T) {
	storeDir := seedStore(t)
	out := t.TempDir()
	h := newHarness()
	h.now = time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)
	code := h.run("report", "--store", "file://"+storeDir, "--from", "2026-11-01", "--to", "2026-11-30",
		"--out", out, "--typst", "no-such-typst-binary")
	if code != 0 || !strings.Contains(h.stderr.String(), "skipping summary.pdf") {
		t.Fatalf("code %d: %s", code, h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(out, "summary.pdf")); err == nil {
		t.Error("summary.pdf should not exist")
	}
	checkFindingsCSV(t, out)
}
