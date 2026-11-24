package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/malware"
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
	// An imported report may list only vulnerable packages, so an SBOM built
	// from it would make later rescans miss new vulnerabilities.
	if opts.TrivyResults != "" {
		opts.SBOM = false
	}

	// Open the store first, so a bad URL fails before a long scan.
	var st store.Store
	if opts.Store != "" {
		if st, err = store.Open(ctx, opts.Store); err != nil {
			return fail(env, err)
		}
	}

	setup, err := loadSetup(opts.PolicyPath, opts.Mode, opts.Exceptions)
	if err != nil {
		return fail(env, err)
	}
	scan, err := scanImage(ctx, opts)
	if err != nil {
		return fail(env, err)
	}
	if opts.Malware.Enabled {
		if scan.Result.Malware, err = scanMalware(ctx, opts, env); err != nil {
			return fail(env, err)
		}
	}
	ci := cicontext.FromEnv(env.Getenv)
	trigger := report.TriggerManual
	if ci.InCI() {
		trigger = report.TriggerCI
	}
	doc, err := buildDocument(env, setup, scan.Result, trigger, ci, nil)
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

// scanMalware unpacks the image and runs ClamAV (and YARA when rules are
// given) on every file.
func scanMalware(ctx context.Context, opts scanOptions, env Env) (*model.MalwareScan, error) {
	m := opts.Malware
	if m.Update {
		updateSignatures(ctx, m, env)
	}
	scanner := malware.Scanner{
		ClamAV:       malware.NewClamAV(m.ClamscanBin, m.ClamAVDB),
		MaxFileBytes: m.MaxFileMB << 20,
		TryDaemon:    m.DockerDaemon,
		WorkDir:      m.WorkDir,
	}
	if m.YaraRules != "" {
		y := malware.NewYara(m.YaraBin, m.YaraRules)
		scanner.Yara = &y
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	result, err := scanner.Scan(ctx, opts.Image)
	if err != nil {
		return nil, fmt.Errorf("malware scan: %w", err)
	}
	return result, nil
}

// updateSignatures runs freshclam. A failed update only warns: the report
// records the signature version that was actually used.
func updateSignatures(ctx context.Context, m malwareOptions, env Env) {
	args := []string{"--stdout", "--no-warnings"}
	if m.ClamAVDB != "" {
		args = append(args, "--datadir="+m.ClamAVDB)
	}
	cmd := exec.CommandContext(ctx, m.FreshclamBin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: warning: freshclam failed, using the existing signatures: %v: %s\n",
			err, strings.TrimSpace(string(out)))
	}
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

// evalSetup is the policy and exceptions every scan in a run is checked with.
type evalSetup struct {
	pol  policy.Policy
	src  policy.Source
	excs []exception.Exception
}

func loadSetup(policyPath string, mode policy.Mode, exceptionsPath string) (evalSetup, error) {
	setup := evalSetup{pol: policy.Default(), src: policy.BuiltinSource()}
	if policyPath != "" {
		var err error
		if setup.pol, setup.src, err = policy.Load(policyPath); err != nil {
			return evalSetup{}, err
		}
	}
	if mode != "" {
		setup.pol = setup.pol.WithMode(mode)
	}
	if exceptionsPath != "" {
		var err error
		if setup.excs, err = exception.Load(exceptionsPath); err != nil {
			return evalSetup{}, err
		}
	}
	return setup, nil
}

// buildDocument applies the policy and exceptions and builds the report.
func buildDocument(env Env, setup evalSetup, res model.ScanResult, trigger string, ci cicontext.Context, rt *report.Runtime) (report.Document, error) {
	now := env.Now().UTC()
	id, err := report.NewReportID(now, nil)
	if err != nil {
		return report.Document{}, err
	}
	return report.Build(report.Input{
		ReportID:     id,
		GeneratedAt:  now,
		Tool:         report.Tool{Name: "scanproof", Version: Version},
		Trigger:      trigger,
		Result:       res,
		Evaluation:   policy.Evaluate(res, setup.pol, setup.excs, now),
		Policy:       setup.pol,
		PolicySource: setup.src,
		Context:      ci,
		Runtime:      rt,
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
