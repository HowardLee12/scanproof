package summary

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

func sampleSummary() Summary {
	return Build(Input{
		ID: "PS-20261001-ABC123", GeneratedAt: time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC),
		Tool: report.Tool{Name: "scanproof", Version: "0.2.0"}, Period: testPeriod(),
		Policy: policy.Default(), StoreLocation: "s3://evidence/prod/", Scans: sampleScans(),
	})
}

func TestMarkdown(t *testing.T) {
	md := Markdown(sampleSummary())
	for _, want := range []string{
		"## ScanProof period summary: 2026-07-01 to 2026-09-30",
		"7 scans",
		"| HIGH | 30 | 2 | 1 | 0 | 39 | 0 | 0 | 1 |",
		"CVE-B",
		"CVE-C",
		"population.csv",
		"PS-20261001-ABC123",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary is missing %q:\n%s", want, md)
		}
	}
}

func TestPDFView(t *testing.T) {
	v := newPDFView(sampleSummary(), map[string]string{"population.csv": "abc", "summary.json": "def"})
	if v.SummaryID != "PS-20261001-ABC123" || v.PeriodLabel != "2026-07-01 to 2026-09-30 · 92 days" {
		t.Errorf("header = %+v", v)
	}
	if len(v.Tiles) != 6 || v.Tiles[0].Value != "7" {
		t.Errorf("tiles = %+v", v.Tiles)
	}
	if len(v.Remediation) != 3 || v.Remediation[1][4] != "0 (0%)" {
		t.Errorf("remediation rows = %+v", v.Remediation)
	}
	if len(v.FixedLate) != 1 || len(v.Overdue) != 1 || len(v.Population) != 7 {
		t.Errorf("late %d overdue %d population %d", len(v.FixedLate), len(v.Overdue), len(v.Population))
	}
	if !hasLabel(v.Evidence, "population.csv SHA-256") {
		t.Errorf("evidence rows = %+v", v.Evidence)
	}
}

func TestRenderPDFUsesTheSharedTemplate(t *testing.T) {
	var files []string
	r := report.PDFRenderer{Bin: "typst"}
	r = r.WithExec(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		root := args[2]
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			files = append(files, e.Name())
		}
		var view pdfView
		raw, _ := os.ReadFile(filepath.Join(root, "data.json"))
		return nil, json.Unmarshal(raw, &view)
	})
	if err := RenderPDF(context.Background(), r, sampleSummary(), nil, filepath.Join(t.TempDir(), "s.pdf")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(files, ",") != "common.typ,data.json,main.typ" {
		t.Fatalf("files = %v", files)
	}
}

func hasLabel(rows []row, label string) bool {
	for _, r := range rows {
		if r.Label == label {
			return true
		}
	}
	return false
}
