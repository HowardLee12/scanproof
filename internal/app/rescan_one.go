package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

// errSkipped marks an image that has no stored SBOM and may not be pulled.
var errSkipped = errors.New("no stored SBOM and --pull-missing=false")

// errNoDirectoryScan marks a directory without a usable stored scan. A
// rescan never has access to the directory itself, so it cannot scan it.
var errNoDirectoryScan = errors.New("no stored scan for this directory; run scanproof scan --dir on a host that has it")

// rescanOutcome is the result for one running image or directory, or an
// inventory source or line that could not be read (where is then set).
type rescanOutcome struct {
	image inventory.RunningImage
	where string
	doc   report.Document
	err   error
}

// label names the outcome for people.
func (o rescanOutcome) label() string {
	if o.where != "" {
		return o.where
	}
	return o.image.Label()
}

// storedScanError is a directory whose stored scans exist but could not be
// used, for example because a file no longer matches its manifest.
type storedScanError struct {
	reportID string
	tried    int
	err      error
}

func (e *storedScanError) Error() string {
	msg := fmt.Sprintf("stored scan %s could not be used: %v", e.reportID, e.err)
	if e.tried > 1 {
		msg += fmt.Sprintf(" (nor could %d older stored scans; see the warnings)", e.tried-1)
	}
	return msg
}

func (e *storedScanError) Unwrap() error { return e.err }

// rescanAll rescans every image and directory, one at a time.
func rescanAll(ctx context.Context, opts rescanOptions, env Env, st store.Store, setup evalSetup, images []inventory.RunningImage) []rescanOutcome {
	outcomes := make([]rescanOutcome, 0, len(images))
	for _, img := range images {
		doc, err := rescanOne(ctx, opts, env, st, setup, img)
		switch {
		case errors.Is(err, errSkipped):
			fmt.Fprintf(env.Stderr, "scanproof: skipping %s: %v\n", img.Label(), err)
		case err != nil:
			fmt.Fprintf(env.Stderr, "scanproof: %s: %v\n", img.Label(), err)
			outcomes = append(outcomes, rescanOutcome{image: img, err: err})
		default:
			fmt.Fprintf(env.Stdout, "%s %s · %d violations · %s\n", doc.Verdict, img.Label(), doc.Summary.Violations, doc.Runtime.Method)
			outcomes = append(outcomes, rescanOutcome{image: img, doc: doc})
		}
	}
	return outcomes
}

// rescanOne checks one running image or deployed directory, from its stored
// SBOM when there is one, and stores the result.
func rescanOne(ctx context.Context, opts rescanOptions, env Env, st store.Store, setup evalSetup, img inventory.RunningImage) (report.Document, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout+time.Minute)
	defer cancel()
	scan, rt, err := rescanScan(ctx, opts, env, st, img)
	if err != nil {
		return report.Document{}, err
	}
	doc, err := buildDocument(env, setup, rescanResult(scan.Result, img), report.TriggerRescan, cicontext.Context{}, rt)
	if err != nil {
		return report.Document{}, err
	}
	perImage := scanOptions{
		OutDir: filepath.Join(opts.OutDir, doc.ReportID), PDF: opts.PDF, SBOM: scan.Raw != nil,
		TrivyBin: opts.TrivyBin, TypstBin: opts.TypstBin, Timeout: opts.Timeout,
	}
	quiet := Env{Getenv: func(string) string { return "" }, Stdout: io.Discard, Stderr: env.Stderr, Now: env.Now}
	written, err := writeEvidence(ctx, perImage, quiet, doc, scan.Raw)
	if err != nil {
		return report.Document{}, err
	}
	if _, err := uploadEvidence(ctx, st, perImage.OutDir, doc, written); err != nil {
		return report.Document{}, err
	}
	return doc, nil
}

// rescanScan checks the stored SBOM, or pulls the image when there is none
// and pulling is allowed. A directory can never be pulled.
func rescanScan(ctx context.Context, opts rescanOptions, env Env, st store.Store, img inventory.RunningImage) (trivy.Scan, *report.Runtime, error) {
	runner := trivy.NewRunner(opts.TrivyBin, opts.Timeout)
	rt := &report.Runtime{Locations: img.Locations}
	scan, from, err := rescanFromSBOM(ctx, env, st, runner, img)
	switch {
	case err != nil:
		return trivy.Scan{}, nil, err
	case from != "":
		rt.Method, rt.SBOMFrom = report.MethodSBOM, from
		scan.Raw = nil // nothing new to convert into an SBOM
		return scan, rt, nil
	case img.Directory:
		return trivy.Scan{}, nil, errNoDirectoryScan
	case !opts.PullMissing:
		return trivy.Scan{}, nil, errSkipped
	}
	if scan, err = runner.Scan(ctx, img.ScanReference()); err != nil {
		return trivy.Scan{}, nil, err
	}
	rt.Method = report.MethodImage
	return scan, rt, nil
}

// rescanResult records what is running, not what the SBOM scan reports: the
// running reference and digest, and for a directory its name and version.
func rescanResult(res model.ScanResult, img inventory.RunningImage) model.ScanResult {
	res.Image.Reference = img.Reference
	if img.Digest != "" {
		res.Image.Digest = img.Digest
	}
	if !img.Directory {
		return res
	}
	name, version, _ := model.ParseDirectoryReference(img.Reference)
	res.ArtifactType = model.ArtifactDirectory
	res.Directory = &model.Directory{Name: name, Version: version, TreeDigest: img.Digest}
	return res
}

// rescanFromSBOM checks the newest stored SBOM of the digest that matches
// its scan's manifest. It returns the report ID the SBOM came from, or ""
// when there is none. A broken SBOM is skipped with a warning, so an image
// can still be pulled and scanned; for a directory, which cannot be pulled,
// stored scans that all fail are an error that names the newest one.
func rescanFromSBOM(ctx context.Context, env Env, st store.Store, runner trivy.Runner, img inventory.RunningImage) (trivy.Scan, string, error) {
	if _, err := store.DigestIndexPrefix(img.Digest); err != nil {
		return trivy.Scan{}, "", nil
	}
	entries, err := store.SBOMEntries(ctx, st, img.Digest)
	if err != nil {
		return trivy.Scan{}, "", err
	}
	var first *storedScanError
	for _, e := range entries {
		scan, err := scanStoredSBOM(ctx, st, runner, e, img)
		if err == nil {
			return scan, e.ReportID, nil
		}
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s: not using the SBOM from %s: %v\n", img.Label(), e.ReportID, err)
		if first == nil {
			first = &storedScanError{reportID: e.ReportID, err: err}
		}
		first.tried++
	}
	if first != nil && img.Directory {
		return trivy.Scan{}, "", first
	}
	return trivy.Scan{}, "", nil
}

func scanStoredSBOM(ctx context.Context, st store.Store, runner trivy.Runner, e store.IndexEntry, img inventory.RunningImage) (trivy.Scan, error) {
	sbom, err := verifiedSBOM(ctx, st, e, img)
	if err != nil {
		return trivy.Scan{}, err
	}
	return runner.ScanSBOM(ctx, sbom)
}

// verifiedSBOM reads an SBOM and checks it against its scan's manifest: the
// same SHA-256, the same digest, and the same kind of artifact, so an image
// scan can never stand in for a directory or the other way round.
func verifiedSBOM(ctx context.Context, st store.Store, e store.IndexEntry, img inventory.RunningImage) ([]byte, error) {
	sbom, err := st.Get(ctx, e.ScanPrefix+sbomFile)
	if err != nil {
		return nil, err
	}
	manifestData, err := st.Get(ctx, e.ScanPrefix+manifestFile)
	if err != nil {
		return nil, err
	}
	m, err := report.VerifyAgainstManifest(manifestData, sbomFile, sbom)
	if err != nil {
		return nil, err
	}
	if m.ImageDigest != img.Digest {
		return nil, fmt.Errorf("the scan is of %s, not %s", m.ImageDigest, img.Digest)
	}
	stored, want := orImage(m.ArtifactType), model.ArtifactContainerImage
	if img.Directory {
		want = model.ArtifactDirectory
	}
	if stored != want {
		return nil, fmt.Errorf("the stored scan is a %s scan, not a %s scan", stored, want)
	}
	return sbom, nil
}

// orImage treats manifests written before directories were supported as
// image scans.
func orImage(artifactType string) string {
	if artifactType == "" {
		return model.ArtifactContainerImage
	}
	return artifactType
}
