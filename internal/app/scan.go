package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

const notifyTimeout = 15 * time.Second

func runScan(ctx context.Context, args []string, env Env) int {
	opts, err := parseScanOptions(args, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	if err != nil {
		return fail(env, err)
	}

	// Open the store first, so a bad URL fails before a long scan.
	var st store.Store
	if opts.Store != "" {
		if st, err = store.Open(ctx, opts.Store); err != nil {
			return fail(env, err)
		}
	}

	scan, err := scanImage(ctx, opts)
	if err != nil {
		return fail(env, err)
	}
	doc, err := evaluate(opts, env, scan.Result)
	if err != nil {
		return fail(env, err)
	}
	written, err := writeEvidence(ctx, opts, env, doc, scan.Raw)
	if err != nil {
		return fail(env, err)
	}
	location := ""
	if st != nil {
		if location, err = uploadEvidence(ctx, st, opts.OutDir, doc, written); err != nil {
			return fail(env, err)
		}
	}
	writeGitHubOutputs(env, doc, opts.OutDir, location)
	sendNotifications(ctx, opts, env, doc)
	announce(env, doc, opts.OutDir, location)

	if doc.Verdict == policy.VerdictFail {
		return ExitViolation
	}
	return ExitOK
}

func fail(env Env, err error) int {
	fmt.Fprintf(env.Stderr, "scanproof: %v\n", err)
	return ExitError
}

// scanImage runs Trivy, or reads an existing Trivy report.
func scanImage(ctx context.Context, opts scanOptions) (trivy.Scan, error) {
	if opts.TrivyResults != "" {
		return importResults(opts.TrivyResults)
	}
	// The context gets a little longer than Trivy's own timeout, so Trivy can
	// report its timeout error instead of being killed.
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout+time.Minute)
	defer cancel()
	return trivy.NewRunner(opts.TrivyBin, opts.Timeout).Scan(ctx, opts.Image)
}

func importResults(path string) (trivy.Scan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return trivy.Scan{}, fmt.Errorf("open trivy results: %w", err)
	}
	res, err := trivy.ParseBytes(raw)
	if err != nil {
		return trivy.Scan{}, err
	}
	if res.ArtifactType != model.ArtifactContainerImage {
		return trivy.Scan{}, fmt.Errorf("%s is a %q report; ScanProof needs a %q report from `trivy image`",
			path, res.ArtifactType, model.ArtifactContainerImage)
	}
	res.Scanner.Imported = true
	return trivy.Scan{Result: res, Raw: raw}, nil
}

// evaluate applies the policy and exceptions and builds the report.
func evaluate(opts scanOptions, env Env, res model.ScanResult) (report.Document, error) {
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

	now := env.Now().UTC()
	id, err := report.NewReportID(now, nil)
	if err != nil {
		return report.Document{}, err
	}
	ci := cicontext.FromEnv(env.Getenv)
	trigger := report.TriggerManual
	if ci.InCI() {
		trigger = report.TriggerCI
	}
	return report.Build(report.Input{
		ReportID:     id,
		GeneratedAt:  now,
		Tool:         report.Tool{Name: "scanproof", Version: Version},
		Trigger:      trigger,
		Result:       res,
		Evaluation:   policy.Evaluate(res, pol, excs, now),
		Policy:       pol,
		PolicySource: src,
		Context:      ci,
	}), nil
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
