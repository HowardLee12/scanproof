package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/stopped"
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
	// notReached are the images and directories a cancelled rescan did not
	// get to.
	notReached []inventory.RunningImage
}

// label names the outcome for people.
func (o rescanOutcome) label() string {
	if o.where != "" {
		return o.where
	}
	return o.image.Label()
}

// rescanAll rescans every image and directory, one at a time. When the
// rescan is cancelled (SIGINT, SIGTERM), it stops and says once what was
// not rescanned.
func rescanAll(ctx context.Context, opts rescanOptions, env Env, st store.Store, setup evalSetup, images []inventory.RunningImage) []rescanOutcome {
	outcomes := make([]rescanOutcome, 0, len(images))
	for i, img := range images {
		if ctx.Err() != nil {
			return append(outcomes, cancelledRescan(env, images[i:]))
		}
		doc, err := rescanOne(ctx, opts, env, st, setup, img)
		err = describeStop(err, opts.Timeout, "the rescan of this "+pick(img.Directory, "directory", "image"))
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

// cancelledRescan reports the images and directories a cancelled rescan
// did not reach, as one failed outcome.
func cancelledRescan(env Env, rest []inventory.RunningImage) rescanOutcome {
	err := fmt.Errorf("the rescan was cancelled; not rescanned: %s", countPhrase(rest, ""))
	fmt.Fprintf(env.Stderr, "scanproof: %v\n", err)
	return rescanOutcome{where: "rescan", err: err, notReached: rest}
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// rescanOne checks one running image or deployed directory, from its stored
// SBOM when there is one, and stores the result.
func rescanOne(ctx context.Context, opts rescanOptions, env Env, st store.Store, setup evalSetup, img inventory.RunningImage) (report.Document, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout+env.timeoutGrace())
	defer cancel()
	scan, rt, err := rescanScan(ctx, opts, env, st, img)
	if err != nil {
		return report.Document{}, stopped.Cause(ctx, err)
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
		return report.Document{}, stopped.Cause(ctx, err)
	}
	if _, err := uploadEvidence(ctx, st, perImage.OutDir, doc, written); err != nil {
		return report.Document{}, stopped.Cause(ctx, err)
	}
	return doc, nil
}

// rescanScan checks the stored SBOM, or pulls the image when there is none
// and pulling is allowed. A directory can never be pulled.
func rescanScan(ctx context.Context, opts rescanOptions, env Env, st store.Store, img inventory.RunningImage) (trivy.Scan, *report.Runtime, error) {
	runner := trivy.NewRunner(opts.TrivyBin, opts.Timeout)
	rt := &report.Runtime{Locations: img.Locations}
	mustUseStored := img.Directory || !opts.PullMissing
	scan, from, err := rescanFromSBOM(ctx, env, st, runner, img, mustUseStored)
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
