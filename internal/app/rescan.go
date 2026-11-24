package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type rescanOptions struct {
	Store       string
	Inventory   string
	Namespace   string
	ECSClusters stringList
	ImagesFile  string
	PolicyPath  string
	Exceptions  string
	OutDir      string
	PDF         bool
	PullMissing bool
	Notify      notify.When
	TrivyBin    string
	TypstBin    string
	Timeout     time.Duration
}

func parseRescanOptions(args []string, stderr io.Writer) (rescanOptions, error) {
	fs := flag.NewFlagSet("scanproof rescan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := rescanOptions{}
	var when string
	fs.StringVar(&opts.Store, "store", "", "evidence store with the earlier scans: s3://bucket/prefix or file:///path (required)")
	fs.StringVar(&opts.Inventory, "inventory", "", "where to find running images: kubernetes, ecs or file (required)")
	fs.StringVar(&opts.Namespace, "namespace", "", "kubernetes: only this namespace (default: all)")
	fs.Var(&opts.ECSClusters, "ecs-cluster", "ecs: cluster name or ARN; repeat for more (default: every cluster in AWS_REGION)")
	fs.StringVar(&opts.ImagesFile, "images-file", "", "file: one image reference per line")
	fs.StringVar(&opts.PolicyPath, "policy", "", "policy file")
	fs.StringVar(&opts.Exceptions, "exceptions", "", "exceptions file that applies to running images")
	fs.StringVar(&opts.OutDir, "out", "scanproof-rescan", "working directory for the evidence files")
	fs.BoolVar(&opts.PDF, "pdf", false, "write a report.pdf for every image")
	fs.BoolVar(&opts.PullMissing, "pull-missing", true, "pull and scan images that have no stored SBOM")
	fs.StringVar(&when, "notify", string(notify.WhenViolation), "when to post one summary to chat: violation, always or never")
	fs.StringVar(&opts.TrivyBin, "trivy", "trivy", "path to the trivy binary")
	fs.StringVar(&opts.TypstBin, "typst", "typst", "path to the typst binary")
	fs.DurationVar(&opts.Timeout, "timeout", 30*time.Minute, "time limit for each image")
	if err := fs.Parse(args); err != nil {
		return rescanOptions{}, err
	}
	switch {
	case fs.NArg() > 0:
		return rescanOptions{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	case opts.Store == "":
		return rescanOptions{}, errors.New("--store is required")
	case opts.Inventory == "":
		return rescanOptions{}, errors.New("--inventory is required (kubernetes, ecs or file)")
	case opts.Timeout <= 0:
		return rescanOptions{}, errors.New("--timeout must be greater than zero")
	}
	w, err := notify.ParseWhen(when)
	if err != nil {
		return rescanOptions{}, err
	}
	opts.Notify = w
	return opts, nil
}

func inventorySource(ctx context.Context, opts rescanOptions) (inventory.Source, error) {
	switch opts.Inventory {
	case "kubernetes":
		return inventory.InCluster(opts.Namespace)
	case "ecs":
		return inventory.NewECS(ctx, opts.ECSClusters)
	case "file":
		if opts.ImagesFile == "" {
			return nil, errors.New("--inventory file needs --images-file")
		}
		return inventory.File{Path: opts.ImagesFile}, nil
	}
	return nil, fmt.Errorf("unknown inventory %q (want kubernetes, ecs or file)", opts.Inventory)
}

// rescanOutcome is the result for one running image.
type rescanOutcome struct {
	image inventory.RunningImage
	doc   report.Document
	err   error
}

func runRescan(ctx context.Context, args []string, env Env) int {
	opts, err := parseRescanOptions(args, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	if err != nil {
		return fail(env, err)
	}
	st, err := store.Open(ctx, opts.Store)
	if err != nil {
		return fail(env, err)
	}
	setup, err := loadSetup(opts.PolicyPath, "", opts.Exceptions)
	if err != nil {
		return fail(env, err)
	}
	source, err := inventorySource(ctx, opts)
	if err != nil {
		return fail(env, err)
	}
	found, err := source.List(ctx)
	if err != nil {
		return fail(env, err)
	}
	images := inventory.Merge(found)

	outcomes := make([]rescanOutcome, 0, len(images))
	for _, img := range images {
		doc, skipped, err := rescanOne(ctx, opts, env, st, setup, img)
		switch {
		case err != nil:
			fmt.Fprintf(env.Stderr, "scanproof: %s: %v\n", img.Reference, err)
			outcomes = append(outcomes, rescanOutcome{image: img, err: err})
		case skipped:
			fmt.Fprintf(env.Stderr, "scanproof: skipping %s: no stored SBOM and --pull-missing=false\n", img.Reference)
		default:
			fmt.Fprintf(env.Stdout, "%s %s · %d violations · %s\n", doc.Verdict, img.Reference, doc.Summary.Violations, doc.Runtime.Method)
			outcomes = append(outcomes, rescanOutcome{image: img, doc: doc})
		}
	}
	sendRescanNotification(ctx, opts, env, outcomes)

	failed := 0
	for _, o := range outcomes {
		if o.err != nil {
			failed++
		}
	}
	fmt.Fprintf(env.Stdout, "ScanProof rescan: %d images rescanned, %d failed, %d running images found\n",
		len(outcomes)-failed, failed, len(images))
	if failed > 0 {
		return ExitError
	}
	return ExitOK
}

// rescanOne checks one running image, from its stored SBOM when there is one.
func rescanOne(ctx context.Context, opts rescanOptions, env Env, st store.Store, setup evalSetup, img inventory.RunningImage) (report.Document, bool, error) {
	runner := trivy.NewRunner(opts.TrivyBin, opts.Timeout)
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout+time.Minute)
	defer cancel()

	rt := &report.Runtime{Locations: img.Locations}
	scan, from, err := rescanFromSBOM(ctx, env, st, runner, img)
	switch {
	case err != nil:
		return report.Document{}, false, err
	case from != "":
		rt.Method, rt.SBOMFrom = report.MethodSBOM, from
		scan.Raw = nil // nothing new to convert into an SBOM
	case opts.PullMissing:
		if scan, err = runner.Scan(ctx, img.ScanReference()); err != nil {
			return report.Document{}, false, err
		}
		rt.Method = report.MethodImage
	default:
		return report.Document{}, true, nil
	}

	res := scan.Result
	res.Image.Reference = img.Reference
	if img.Digest != "" {
		res.Image.Digest = img.Digest
	}
	doc, err := buildDocument(env, setup, res, report.TriggerRescan, cicontext.Context{}, rt)
	if err != nil {
		return report.Document{}, false, err
	}
	perImage := scanOptions{
		OutDir: filepath.Join(opts.OutDir, doc.ReportID), PDF: opts.PDF, SBOM: scan.Raw != nil,
		TrivyBin: opts.TrivyBin, TypstBin: opts.TypstBin, Timeout: opts.Timeout,
	}
	quiet := Env{Getenv: func(string) string { return "" }, Stdout: io.Discard, Stderr: env.Stderr, Now: env.Now}
	written, err := writeEvidence(ctx, perImage, quiet, doc, scan.Raw)
	if err != nil {
		return report.Document{}, false, err
	}
	if _, err := uploadEvidence(ctx, st, perImage.OutDir, doc, written); err != nil {
		return report.Document{}, false, err
	}
	return doc, false, nil
}

// rescanFromSBOM checks the newest stored SBOM of the image's digest that
// matches its scan's manifest. It returns the report ID the SBOM came from,
// or "" when no usable SBOM exists; a broken SBOM is skipped with a warning
// so the image can still be pulled and scanned.
func rescanFromSBOM(ctx context.Context, env Env, st store.Store, runner trivy.Runner, img inventory.RunningImage) (trivy.Scan, string, error) {
	if _, err := store.DigestIndexPrefix(img.Digest); err != nil {
		return trivy.Scan{}, "", nil
	}
	entries, err := store.SBOMEntries(ctx, st, img.Digest)
	if err != nil {
		return trivy.Scan{}, "", err
	}
	for _, e := range entries {
		sbom, err := verifiedSBOM(ctx, st, e, img.Digest)
		if err == nil {
			scan, scanErr := runner.ScanSBOM(ctx, sbom)
			if scanErr == nil {
				return scan, e.ReportID, nil
			}
			err = scanErr
		}
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s: not using the SBOM from %s: %v\n", img.Reference, e.ReportID, err)
	}
	return trivy.Scan{}, "", nil
}

// verifiedSBOM reads an SBOM and checks it against its scan's manifest: same
// SHA-256 and the same image digest.
func verifiedSBOM(ctx context.Context, st store.Store, e store.IndexEntry, digest string) ([]byte, error) {
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
	if m.ImageDigest != digest {
		return nil, fmt.Errorf("the scan is of %s, not %s", m.ImageDigest, digest)
	}
	return sbom, nil
}

// sendRescanNotification posts one summary for the whole run.
func sendRescanNotification(ctx context.Context, opts rescanOptions, env Env, outcomes []rescanOutcome) {
	verdict := policy.VerdictPass
	lines := []string{}
	failed := 0
	for _, o := range outcomes {
		switch {
		case o.err != nil:
			failed++
			lines = append(lines, fmt.Sprintf("%s: scan failed", o.image.Reference))
		case o.doc.Summary.Violations > 0:
			verdict = policy.VerdictWarn
			lines = append(lines, fmt.Sprintf("%s: %d violations", o.image.Reference, o.doc.Summary.Violations))
		}
	}
	if failed > 0 {
		verdict = policy.VerdictWarn
	}
	if !notify.ShouldNotify(opts.Notify, verdict) {
		return
	}
	targets := notify.TargetsFromEnv(env.Getenv)
	if len(targets) == 0 {
		return
	}
	shown, more := lines, 0
	if len(shown) > 10 {
		shown, more = lines[:10], len(lines)-10
	}
	msg := notify.Message{
		Verdict:        verdict,
		Title:          fmt.Sprintf("ScanProof rescan: %d of %d running images need attention", len(lines), len(outcomes)),
		Summary:        fmt.Sprintf("Rescanned %d running images against today's vulnerability database", len(outcomes)),
		Violations:     shown,
		MoreViolations: more,
		ReportID:       "rescan " + env.Now().UTC().Format("2006-01-02"),
	}
	client := env.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: notifyTimeout}
	}
	sender := notify.Sender{Client: client, UserAgent: "scanproof/" + Version + " (+https://github.com/HowardLee12/scanproof)"}
	for _, t := range targets {
		if err := sender.Send(ctx, t, msg); err != nil {
			fmt.Fprintf(env.Stderr, "scanproof: warning: %s notification failed: %v\n", t.Name, err)
		}
	}
}
