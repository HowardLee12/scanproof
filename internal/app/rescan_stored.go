package app

import (
	"context"
	"fmt"

	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/stopped"
	"github.com/HowardLee12/scanproof/internal/store"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

// storedScanError is an image or directory whose stored scans exist but
// could not be used, for example because a file no longer matches its
// manifest.
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

// indexError is a digest whose index entries exist but none can be read.
type indexError struct{ unusable int }

func (e *indexError) Error() string {
	return pluralize(e.unusable, "stored index entry for this digest could not be read",
		"stored index entries for this digest could not be read") + "; check the store's index/ folder"
}

// rescanFromSBOM checks the newest stored SBOM of the digest that matches
// its scan's manifest. It returns the report ID the SBOM came from, or ""
// when there is none. When the caller cannot fall back to pulling the image
// (mustUseStored: a directory, or --pull-missing=false), stored scans or
// index entries that exist but cannot be used are an error that says why;
// otherwise they are warnings and the image is pulled.
func rescanFromSBOM(ctx context.Context, env Env, st store.Store, runner trivy.Runner, img inventory.RunningImage, mustUseStored bool) (trivy.Scan, string, error) {
	if _, err := store.DigestIndexPrefix(img.Digest); err != nil {
		return trivy.Scan{}, "", nil
	}
	entries, unusable, err := store.SBOMEntries(ctx, st, img.Digest)
	if err != nil {
		return trivy.Scan{}, "", err
	}
	var first *storedScanError
	for _, e := range entries {
		scan, err := scanStoredSBOM(ctx, st, runner, e, img)
		if err == nil {
			return scan, e.ReportID, nil
		}
		if stopped.Check(ctx) != nil {
			return trivy.Scan{}, "", err // out of time: no older scan, no pull
		}
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s: not using the SBOM from %s: %v\n", img.Label(), e.ReportID, err)
		if first == nil {
			first = &storedScanError{reportID: e.ReportID, err: err}
		}
		first.tried++
	}
	switch {
	case first != nil && mustUseStored:
		return trivy.Scan{}, "", first
	case unusable > 0 && first == nil && mustUseStored:
		return trivy.Scan{}, "", &indexError{unusable: unusable}
	case unusable > 0:
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s: %v\n", img.Label(), &indexError{unusable: unusable})
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
