package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

const (
	resultsFile  = "results.json"
	summaryFile  = "summary.md"
	pdfFile      = "report.pdf"
	sbomFile     = "sbom.cdx.json"
	manifestFile = "manifest.json"
	dirMode      = 0o755
)

var contentTypes = map[string]string{
	".json": "application/json",
	".md":   "text/markdown; charset=utf-8",
	".pdf":  "application/pdf",
}

// writeEvidence writes every output file, then the manifest that hashes them.
// It returns the names of the files written, manifest last.
func writeEvidence(ctx context.Context, opts scanOptions, env Env, doc report.Document, raw []byte) ([]string, error) {
	if err := os.MkdirAll(opts.OutDir, dirMode); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	path := func(name string) string { return filepath.Join(opts.OutDir, name) }

	// Optional files from an earlier run must never sit next to new results.
	for _, name := range []string{pdfFile, sbomFile} {
		if err := os.Remove(path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove old %s: %w", name, err)
		}
	}

	if err := report.WriteJSON(path(resultsFile), doc); err != nil {
		return nil, err
	}
	resultsHash, _, err := report.HashFile(path(resultsFile))
	if err != nil {
		return nil, err
	}
	summary := report.Markdown(doc)
	if err := report.WriteFile(path(summaryFile), []byte(summary)); err != nil {
		return nil, err
	}
	written := []string{resultsFile, summaryFile}

	if opts.SBOM && writeSBOM(ctx, opts, env, raw) {
		written = append(written, sbomFile)
	}
	if opts.PDF && writePDF(ctx, opts, env, doc, resultsHash) {
		written = append(written, pdfFile)
	}

	manifest, err := report.BuildManifest(opts.OutDir, doc, written)
	if err != nil {
		return nil, err
	}
	if err := report.WriteJSON(path(manifestFile), manifest); err != nil {
		return nil, err
	}
	writeGitHubStepSummary(env, doc.Context.StepSummaryPath, summary)
	return append(written, manifestFile), nil
}

// writeSBOM never fails the scan; the SBOM only speeds up later rescans.
func writeSBOM(ctx context.Context, opts scanOptions, env Env, raw []byte) bool {
	sbom, err := trivy.NewRunner(opts.TrivyBin, opts.Timeout).SBOM(ctx, raw)
	if err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %v; skipping %s\n", err, sbomFile)
		return false
	}
	if err := report.WriteFile(filepath.Join(opts.OutDir, sbomFile), sbom); err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %v; skipping %s\n", err, sbomFile)
		return false
	}
	return true
}

// writePDF never fails the scan: the JSON and Markdown evidence already exist.
func writePDF(ctx context.Context, opts scanOptions, env Env, doc report.Document, resultsHash string) bool {
	renderer := report.NewPDFRenderer(opts.TypstBin)
	if !renderer.Available() {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s not found; skipping %s\n", opts.TypstBin, pdfFile)
		return false
	}
	if err := renderer.Render(ctx, doc, resultsHash, filepath.Join(opts.OutDir, pdfFile)); err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %v; skipping %s\n", err, pdfFile)
		return false
	}
	return true
}

// uploadEvidence copies the written files to the store, manifest last, and
// returns the location of the scan's folder. A failure is an error: evidence
// that was configured to be kept must not go missing silently.
func uploadEvidence(ctx context.Context, st store.Store, outDir string, doc report.Document, names []string) (string, error) {
	prefix := store.ScanPrefix(doc.ReportID, doc.GeneratedAt)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			return "", fmt.Errorf("read %s for upload: %w", name, err)
		}
		if err := st.Put(ctx, prefix+name, data, contentType(name)); err != nil {
			return "", err
		}
	}
	return st.Location(prefix), nil
}

func contentType(name string) string {
	for ext, ct := range contentTypes {
		if strings.HasSuffix(name, ext) {
			return ct
		}
	}
	return "application/octet-stream"
}
