package report

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderPDFWritesTemplateAndDataThenRunsTypst(t *testing.T) {
	var args []string
	var data pdfView
	var template string
	fake := func(_ context.Context, name string, a ...string) ([]byte, error) {
		args = append([]string{name}, a...)
		root := a[indexOf(a, "--root")+1]
		raw, err := os.ReadFile(filepath.Join(root, "data.json"))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, err
		}
		tpl, err := os.ReadFile(filepath.Join(root, "report.typ"))
		template = string(tpl)
		return nil, err
	}

	out := filepath.Join(t.TempDir(), "report.pdf")
	r := PDFRenderer{Bin: "typst", exec: fake}
	if err := r.Render(context.Background(), sampleDocument(t), "abc123", out); err != nil {
		t.Fatal(err)
	}

	cmd := strings.Join(args, " ")
	for _, want := range []string{"typst compile", "--root", "--creation-timestamp " + "1795508208", out} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command %q is missing %q", cmd, want)
		}
	}
	if data.ReportID != "SR-20261124-7F3A9C" || data.Verdict != "WARN" {
		t.Errorf("data.json not written correctly: %+v", data.ReportID)
	}
	if !strings.Contains(template, `json("data.json")`) {
		t.Error("template should read data.json")
	}
}

func TestRenderPDFReportsTypstFailure(t *testing.T) {
	r := PDFRenderer{Bin: "typst", exec: func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("error: unknown variable")
	}}
	err := r.Render(context.Background(), sampleDocument(t), "", filepath.Join(t.TempDir(), "r.pdf"))
	if err == nil || !strings.Contains(err.Error(), "unknown variable") {
		t.Fatalf("expected the typst error, got %v", err)
	}
}

func TestRendererAvailability(t *testing.T) {
	if NewPDFRenderer("definitely-not-a-real-binary-xyz").Available() {
		t.Error("a missing binary is not available")
	}
	if !NewPDFRenderer("sh").Available() {
		t.Error("sh should be found on PATH")
	}
}

// TestRenderPDFWithRealTypst runs only where the typst binary is installed,
// such as inside the release image.
func TestRenderPDFWithRealTypst(t *testing.T) {
	if _, err := exec.LookPath("typst"); err != nil {
		t.Skip("typst is not installed")
	}
	out := filepath.Join(t.TempDir(), "report.pdf")
	// SCANPROOF_TEST_PDF_OUT keeps the rendered file for manual review.
	if keep := os.Getenv("SCANPROOF_TEST_PDF_OUT"); keep != "" {
		out = keep
	}
	if err := NewPDFRenderer("typst").Render(context.Background(), sampleDocument(t), "abc123", out); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 5)
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Read(head); err != nil || string(head) != "%PDF-" {
		t.Fatalf("output is not a PDF: %q %v", head, err)
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
