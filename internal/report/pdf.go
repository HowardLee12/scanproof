package report

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/stopped"
)

//go:embed templates/common.typ
var commonTemplate []byte

//go:embed templates/report.typ
var reportTemplate []byte

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// PDFRenderer produces auditor-facing PDFs with Typst.
type PDFRenderer struct {
	Bin  string
	exec execFunc
}

// NewPDFRenderer returns a renderer that runs the Typst binary at bin.
func NewPDFRenderer(bin string) PDFRenderer {
	return PDFRenderer{Bin: bin, exec: runCommand}
}

// WithExec returns a copy that runs commands with fn, for tests.
func (r PDFRenderer) WithExec(fn func(ctx context.Context, name string, args ...string) ([]byte, error)) PDFRenderer {
	r.exec = fn
	return r
}

// Available reports whether the Typst binary can be found.
func (r PDFRenderer) Available() bool {
	_, err := exec.LookPath(r.Bin)
	return err == nil
}

// Render writes the scan report PDF for doc. resultsSHA256 is printed in the
// report so a reader can check it against results.json.
func (r PDFRenderer) Render(ctx context.Context, doc Document, resultsSHA256, outPath string) error {
	return r.RenderTemplate(ctx, reportTemplate, newPDFView(doc, resultsSHA256), doc.GeneratedAt, outPath)
}

// RenderTemplate renders a Typst template with data written to data.json.
// The template can import the shared helpers from "common.typ".
func (r PDFRenderer) RenderTemplate(ctx context.Context, template []byte, data any, created time.Time, outPath string) error {
	dir, err := os.MkdirTemp("", "scanproof-pdf-")
	if err != nil {
		return fmt.Errorf("create PDF work directory: %w", err)
	}
	defer os.RemoveAll(dir)

	for name, content := range map[string][]byte{"common.typ": commonTemplate, "main.typ": template} {
		if err := WriteFile(filepath.Join(dir, name), content); err != nil {
			return err
		}
	}
	if err := WriteJSON(filepath.Join(dir, "data.json"), data); err != nil {
		return err
	}

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", outPath, err)
	}
	// A fixed creation time keeps the PDF identical for identical input.
	_, err = r.exec(ctx, r.Bin, "compile",
		"--root", dir,
		"--creation-timestamp", strconv.FormatInt(created.Unix(), 10),
		filepath.Join(dir, "main.typ"), absOut)
	if err != nil {
		return fmt.Errorf("render PDF with typst: %w", err)
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := stopped.Command(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stop := stopped.Killed(ctx, err); stop != nil {
			return nil, stopped.InPhase(stop, "making the PDF")
		}
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
