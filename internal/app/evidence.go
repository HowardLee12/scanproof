package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/stopped"
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
	".csv":  "text/csv; charset=utf-8",
	".json": "application/json",
	".md":   "text/markdown; charset=utf-8",
	".pdf":  "application/pdf",
}

// writeEvidence writes every output file, then the manifest that hashes them.
// It returns the names of the files written, manifest last. The SBOM is made
// first, so a scan that needs it and cannot have it writes nothing.
func writeEvidence(ctx context.Context, opts scanOptions, env Env, doc report.Document, raw []byte) ([]string, error) {
	sbom, err := makeSBOM(ctx, opts, env, raw)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.OutDir, dirMode); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	path := func(name string) string { return filepath.Join(opts.OutDir, name) }

	// Files from an earlier run must never sit next to new results: the
	// optional ones may not be written again, and the manifest is written
	// last, so a run that stops on the way must not leave the old one.
	for _, name := range []string{manifestFile, pdfFile, sbomFile} {
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
	optional, err := writeOptional(ctx, opts, env, doc, sbom, resultsHash)
	if err != nil {
		return nil, err
	}
	written := append([]string{resultsFile, summaryFile}, optional...)

	manifest, err := report.BuildManifest(opts.OutDir, doc, written)
	if err != nil {
		return nil, err
	}
	if err := report.WriteJSON(path(manifestFile), manifest); err != nil {
		return nil, err
	}
	return append(written, manifestFile), nil
}

// writeOptional writes the SBOM, when there is one, and the PDF, when it is
// wanted and can be made. It returns the names it wrote.
func writeOptional(ctx context.Context, opts scanOptions, env Env, doc report.Document, sbom []byte, resultsHash string) ([]string, error) {
	written := []string{}
	if sbom != nil {
		if err := report.WriteFile(filepath.Join(opts.OutDir, sbomFile), sbom); err != nil {
			return nil, err
		}
		written = append(written, sbomFile)
	}
	if !opts.PDF {
		return written, nil
	}
	made, err := writePDF(ctx, opts, env, doc, resultsHash)
	if err != nil || !made {
		return written, err
	}
	return append(written, pdfFile), nil
}

// makeSBOM converts Trivy's report into an SBOM. For an image it is only a
// shortcut for later rescans, so a failure just warns. A stored directory
// scan without an SBOM could never be rescanned, so there it is an error,
// returned before any evidence is written.
func makeSBOM(ctx context.Context, opts scanOptions, env Env, raw []byte) ([]byte, error) {
	if !opts.SBOM {
		return nil, nil
	}
	sbom, err := trivy.NewRunner(opts.TrivyBin, opts.Timeout).SBOM(ctx, raw)
	if err == nil {
		return sbom, nil
	}
	if stopped.Is(err) {
		return nil, err
	}
	if opts.Dir.Enabled && opts.Store != "" {
		return nil, fmt.Errorf("the directory's SBOM could not be made, so scanproof rescan could never check it; "+
			"nothing was written or stored: %w", err)
	}
	fmt.Fprintf(env.Stderr, "scanproof: warning: %v; skipping %s\n", err, sbomFile)
	return nil, nil
}

// writePDF only warns when the PDF cannot be made: the JSON and Markdown
// evidence already exist. A scan that was stopped or cancelled meanwhile is
// an error.
func writePDF(ctx context.Context, opts scanOptions, env Env, doc report.Document, resultsHash string) (bool, error) {
	renderer := report.NewPDFRenderer(opts.TypstBin)
	if !renderer.Available() {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s not found; skipping %s\n", opts.TypstBin, pdfFile)
		return false, nil
	}
	if err := renderer.Render(ctx, doc, resultsHash, filepath.Join(opts.OutDir, pdfFile)); err != nil {
		if stopped.Is(err) {
			return false, err
		}
		fmt.Fprintf(env.Stderr, "scanproof: warning: %v; skipping %s\n", err, pdfFile)
		return false, nil
	}
	return true, nil
}

// uploadEvidence copies the written files to the store, manifest last, and
// returns the location of the scan's folder. A failure is an error: evidence
// that was configured to be kept must not go missing silently.
func uploadEvidence(ctx context.Context, st store.Store, outDir string, doc report.Document, names []string) (string, error) {
	prefix := store.ScanPrefix(doc.ReportID, doc.GeneratedAt)
	if err := uploadFiles(ctx, st, outDir, prefix, names); err != nil {
		return "", err
	}
	// The digest index lets rescans find this scan's SBOM later. Only scans
	// that saved an SBOM are indexed, so the index stays small.
	if _, err := store.DigestIndexPrefix(doc.Image.Digest); err == nil && contains(names, sbomFile) {
		entry := store.IndexEntry{ReportID: doc.ReportID, ScanPrefix: prefix, HasSBOM: true}
		if err := store.PutIndexEntry(ctx, st, doc.Image.Digest, entry); err != nil {
			return "", fmt.Errorf("report %s is stored but not indexed, so rescans will not find it (stored at %s): %w",
				doc.ReportID, st.Location(prefix), err)
		}
	}
	return st.Location(prefix), nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// uploadFiles copies files from dir to the store under prefix, in order.
func uploadFiles(ctx context.Context, st store.Store, dir, prefix string, names []string) error {
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read %s for upload: %w", name, err)
		}
		if err := st.Put(ctx, prefix+name, data, contentType(name)); err != nil {
			return stopped.InPhase(stopped.Cause(ctx, err), "while storing the evidence")
		}
	}
	return nil
}

func contentType(name string) string {
	for ext, ct := range contentTypes {
		if strings.HasSuffix(name, ext) {
			return ct
		}
	}
	return "application/octet-stream"
}
