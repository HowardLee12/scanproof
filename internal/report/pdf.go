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
)

//go:embed templates/report.typ
var reportTemplate []byte

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// PDFRenderer produces the auditor-facing PDF with Typst.
type PDFRenderer struct {
	Bin  string
	exec execFunc
}

// NewPDFRenderer returns a renderer that runs the Typst binary at bin.
func NewPDFRenderer(bin string) PDFRenderer {
	return PDFRenderer{Bin: bin, exec: runCommand}
}

// Available reports whether the Typst binary can be found.
func (r PDFRenderer) Available() bool {
	_, err := exec.LookPath(r.Bin)
	return err == nil
}

// Render writes the PDF for doc to outPath. resultsSHA256 is printed in the
// report so a reader can check it against results.json.
func (r PDFRenderer) Render(ctx context.Context, doc Document, resultsSHA256, outPath string) error {
	dir, err := os.MkdirTemp("", "scanproof-pdf-")
	if err != nil {
		return fmt.Errorf("create PDF work directory: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := WriteFile(filepath.Join(dir, "report.typ"), reportTemplate); err != nil {
		return err
	}
	if err := WriteJSON(filepath.Join(dir, "data.json"), newPDFView(doc, resultsSHA256)); err != nil {
		return err
	}

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", outPath, err)
	}
	// A fixed creation time keeps the PDF identical for identical input.
	_, err = r.exec(ctx, r.Bin, "compile",
		"--root", dir,
		"--creation-timestamp", strconv.FormatInt(doc.GeneratedAt.Unix(), 10),
		filepath.Join(dir, "report.typ"), absOut)
	if err != nil {
		return fmt.Errorf("render PDF with typst: %w", err)
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
