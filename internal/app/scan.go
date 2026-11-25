package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/malware"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/stopped"
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
	done, err := scanAndStore(ctx, opts, env)
	if err != nil {
		return fail(env, describeStop(err, opts.Timeout, "the scan"))
	}
	doc := done.doc
	writeGitHubStepSummary(env, doc.Context.StepSummaryPath, report.Markdown(doc))
	writeGitHubOutputs(env, doc, opts.OutDir, done.location)
	sendNotifications(ctx, opts, env, doc)
	announce(env, doc, opts.OutDir, done.location)
	announceInventoryLine(env, doc, done.indexed)

	if doc.Verdict == policy.VerdictFail {
		return ExitViolation
	}
	return ExitOK
}

// scanned is a finished scan: the report, where it was stored, and whether
// it was stored with an SBOM and indexed, so rescans can check it.
type scanned struct {
	doc      report.Document
	location string
	indexed  bool
}

// scanAndStore scans, writes the evidence files and uploads them when a
// store is configured.
func scanAndStore(ctx context.Context, opts scanOptions, env Env) (scanned, error) {
	// Open the store first, so a bad URL fails before a long scan.
	var st store.Store
	if opts.Store != "" {
		var err error
		if st, err = store.Open(ctx, opts.Store); err != nil {
			return scanned{}, err
		}
	}
	setup, err := loadSetup(opts.PolicyPath, opts.Mode, opts.Exceptions)
	if err != nil {
		return scanned{}, err
	}
	// One deadline for the whole scan, including both reads of a directory
	// and the malware scan. Trivy alone stops at --timeout, so it can report
	// its own timeout before this context ends.
	scanCtx, cancel := context.WithTimeout(ctx, opts.Timeout+timeoutGrace)
	defer cancel()
	scan, err := scanTarget(scanCtx, opts, env)
	if err != nil {
		return scanned{}, err
	}
	ci := cicontext.FromEnv(env.Getenv)
	doc, err := buildDocument(env, setup, scan.Result, scanTrigger(ci), ci, nil)
	if err != nil {
		return scanned{}, err
	}
	written, err := writeEvidence(ctx, opts, env, doc, scan.Raw)
	if err != nil || st == nil {
		return scanned{doc: doc}, err
	}
	location, err := uploadEvidence(ctx, st, opts.OutDir, doc, written)
	return scanned{doc: doc, location: location, indexed: contains(written, sbomFile)}, err
}

func scanTrigger(ci cicontext.Context) string {
	if ci.InCI() {
		return report.TriggerCI
	}
	return report.TriggerManual
}

// scanTarget scans the directory or the image, and the image for malware
// when asked to.
func scanTarget(ctx context.Context, opts scanOptions, env Env) (trivy.Scan, error) {
	if opts.Dir.Enabled {
		return scanDirectory(ctx, opts, env)
	}
	opts = withMalwarePlatform(opts)
	scan, err := scanImage(ctx, opts)
	if err != nil {
		return scan, err
	}
	if c := trivy.VersionCaveat(scan.Result.Scanner.Version); c != "" && !scan.Result.Scanner.Imported {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s\n", c)
	}
	if !opts.Malware.Enabled {
		return scan, nil
	}
	m, err := scanMalware(ctx, opts, env)
	if err != nil {
		return trivy.Scan{}, err
	}
	if err := sameImage(scan.Result.Image.ImageID, m.ConfigDigest); err != nil {
		return trivy.Scan{}, err
	}
	scan.Result.Malware = m
	return scan, nil
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
	runner := trivy.NewRunner(opts.TrivyBin, opts.Timeout)
	runner.Platform = opts.Platform
	return runner.Scan(ctx, opts.Image)
}

// withMalwarePlatform picks one platform for both scans when a malware scan
// runs: without one, Trivy pulls linux/amd64 from a registry on any machine
// while the malware scan pulls the machine's own platform. (An image found
// in the Docker daemon is used as it is by both.)
func withMalwarePlatform(opts scanOptions) scanOptions {
	if opts.Malware.Enabled && opts.Platform == "" {
		opts.Platform = "linux/" + runtime.GOARCH
	}
	return opts
}

// sameImage makes sure the vulnerability and malware scans looked at the same
// image (the local daemon and the registry can hold different images under
// one tag, and multi-platform images have one image per platform).
func sameImage(trivyImageID, malwareConfig string) error {
	if trivyImageID == "" || malwareConfig == "" || trivyImageID == malwareConfig {
		return nil
	}
	return fmt.Errorf("the malware scan read image %s but the vulnerability scan read %s; "+
		"set --platform, or pull the image so the Docker daemon and the registry agree", malwareConfig, trivyImageID)
}

// scanMalware unpacks the image and runs ClamAV (and YARA when rules are
// given) on every file.
func scanMalware(ctx context.Context, opts scanOptions, env Env) (*model.MalwareScan, error) {
	m := opts.Malware
	if m.Update {
		if err := updateSignatures(ctx, m, env); err != nil {
			return nil, err
		}
	}
	if m.WorkDir != "" {
		// The Docker daemon export is buffered in a temporary file; keep it
		// on the disk chosen for the scan.
		os.Setenv("TMPDIR", m.WorkDir)
	}
	result, err := malwareScanner(opts, env).Scan(ctx, opts.Image)
	if err != nil {
		return nil, fmt.Errorf("malware scan: %w", err)
	}
	return result, nil
}

// malwareScanner configures the engines from the command line.
func malwareScanner(opts scanOptions, env Env) malware.Scanner {
	m := opts.Malware
	scanner := malware.Scanner{
		ClamAV:       malware.NewClamAV(m.ClamscanBin, m.ClamAVDB),
		MaxFileBytes: m.MaxFileMB << 20,
		TryDaemon:    m.DockerDaemon,
		WorkDir:      m.WorkDir,
		Platform:     opts.Platform,
		Warn:         func(msg string) { fmt.Fprintf(env.Stderr, "scanproof: warning: %s\n", msg) },
		Progress:     func(msg string) { fmt.Fprintf(env.Stderr, "scanproof: %s\n", msg) },
	}
	if m.YaraRules != "" {
		y := malware.NewYara(m.YaraBin, m.YaraRules)
		scanner.Yara = &y
	}
	return scanner
}

// updateSignatures runs freshclam. A failed update only warns: the report
// records the signature version that was actually used.
func updateSignatures(ctx context.Context, m malwareOptions, env Env) error {
	args := []string{"--stdout", "--no-warnings"}
	if m.ClamAVDB != "" {
		args = append(args, "--datadir="+m.ClamAVDB)
	}
	cmd := stopped.Command(ctx, m.FreshclamBin, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if stop := stopped.Check(ctx); stop != nil {
		return stopped.InPhase(stop, "the ClamAV signature update")
	}
	fmt.Fprintf(env.Stderr, "scanproof: warning: freshclam failed, using the existing signatures: %v: %s\n",
		err, strings.TrimSpace(string(out)))
	return nil
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
