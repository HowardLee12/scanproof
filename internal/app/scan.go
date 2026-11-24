package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

const (
	resultsFile   = "results.json"
	summaryFile   = "summary.md"
	pdfFile       = "report.pdf"
	manifestFile  = "manifest.json"
	dirMode       = 0o755
	notifyTimeout = 15 * time.Second
)

func runScan(ctx context.Context, args []string, env Env) int {
	opts, err := parseScanOptions(args, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: %v\n", err)
		return ExitError
	}

	doc, err := evaluate(ctx, opts, env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: %v\n", err)
		return ExitError
	}
	if err := writeEvidence(ctx, opts, env, doc); err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: %v\n", err)
		return ExitError
	}
	sendNotifications(ctx, opts, env, doc)
	announce(env, doc, opts.OutDir)

	if doc.Verdict == policy.VerdictFail {
		return ExitViolation
	}
	return ExitOK
}

// evaluate loads the inputs, runs or reads the scan and builds the report.
func evaluate(ctx context.Context, opts scanOptions, env Env) (report.Document, error) {
	pol, src := policy.Default(), policy.BuiltinSource()
	if opts.PolicyPath != "" {
		var err error
		if pol, src, err = policy.Load(opts.PolicyPath); err != nil {
			return report.Document{}, err
		}
	}
	if opts.Mode != "" {
		pol = pol.WithMode(opts.Mode)
	}

	var excs []exception.Exception
	if opts.Exceptions != "" {
		var err error
		if excs, err = exception.Load(opts.Exceptions); err != nil {
			return report.Document{}, err
		}
	}

	res, err := scanImage(ctx, opts)
	if err != nil {
		return report.Document{}, err
	}

	now := env.Now().UTC()
	id, err := report.NewReportID(now, nil)
	if err != nil {
		return report.Document{}, err
	}
	return report.Build(report.Input{
		ReportID:     id,
		GeneratedAt:  now,
		Tool:         report.Tool{Name: "scanproof", Version: Version},
		Result:       res,
		Evaluation:   policy.Evaluate(res, pol, excs, now),
		Policy:       pol,
		PolicySource: src,
		Context:      cicontext.FromEnv(env.Getenv),
	}), nil
}

func scanImage(ctx context.Context, opts scanOptions) (model.ScanResult, error) {
	if opts.TrivyResults != "" {
		f, err := os.Open(opts.TrivyResults)
		if err != nil {
			return model.ScanResult{}, fmt.Errorf("open trivy results: %w", err)
		}
		defer f.Close()
		res, err := trivy.Parse(f)
		if err != nil {
			return model.ScanResult{}, err
		}
		if res.ArtifactType != model.ArtifactContainerImage {
			return model.ScanResult{}, fmt.Errorf("%s is a %q report; ScanProof needs a %q report from `trivy image`",
				opts.TrivyResults, res.ArtifactType, model.ArtifactContainerImage)
		}
		res.Scanner.Imported = true
		return res, nil
	}
	// The context gets a little longer than Trivy's own timeout, so Trivy can
	// report its timeout error instead of being killed.
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout+time.Minute)
	defer cancel()
	return trivy.NewRunner(opts.TrivyBin, opts.Timeout).Scan(ctx, opts.Image)
}

// writeEvidence writes every output file, then the manifest that hashes them.
func writeEvidence(ctx context.Context, opts scanOptions, env Env, doc report.Document) error {
	if err := os.MkdirAll(opts.OutDir, dirMode); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	path := func(name string) string { return filepath.Join(opts.OutDir, name) }

	// A PDF from an earlier run must never sit next to new results.
	if err := os.Remove(path(pdfFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove old %s: %w", pdfFile, err)
	}

	if err := report.WriteJSON(path(resultsFile), doc); err != nil {
		return err
	}
	resultsHash, _, err := report.HashFile(path(resultsFile))
	if err != nil {
		return err
	}
	summary := report.Markdown(doc)
	if err := report.WriteFile(path(summaryFile), []byte(summary)); err != nil {
		return err
	}
	written := []string{resultsFile, summaryFile}

	if opts.PDF {
		if wrote := writePDF(ctx, opts, env, doc, resultsHash); wrote {
			written = append(written, pdfFile)
		}
	}

	manifest, err := report.BuildManifest(opts.OutDir, doc, written)
	if err != nil {
		return err
	}
	if err := report.WriteJSON(path(manifestFile), manifest); err != nil {
		return err
	}

	writeGitHubStepSummary(env, doc.Context.StepSummaryPath, summary)
	writeGitHubOutputs(env, doc, opts.OutDir)
	return nil
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

func sendNotifications(ctx context.Context, opts scanOptions, env Env, doc report.Document) {
	if !notify.ShouldNotify(opts.Notify, doc.Verdict) {
		return
	}
	targets := notify.TargetsFromEnv(env.Getenv)
	if len(targets) == 0 {
		return
	}
	client := env.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: notifyTimeout}
	}
	sender := notify.Sender{Client: client, UserAgent: "scanproof/" + Version + " (+https://github.com/HowardLee12/scanproof)"}
	msg := notify.NewMessage(doc)
	for _, t := range targets {
		if err := sender.Send(ctx, t, msg); err != nil {
			fmt.Fprintf(env.Stderr, "scanproof: warning: %s notification failed: %v\n", t.Name, err)
		}
	}
}
