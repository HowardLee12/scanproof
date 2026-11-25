package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/store"
)

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// knownInventories are the places a rescan can find what is running.
var knownInventories = []string{"kubernetes", "ecs", "file"}

type rescanOptions struct {
	Store       string
	Inventories []string
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
	var inventories, when string
	fs.StringVar(&opts.Store, "store", "", "evidence store with the earlier scans: s3://bucket/prefix or file:///path (required)")
	fs.StringVar(&inventories, "inventory", "", "where to find what runs: kubernetes, ecs or file, or a comma-separated list such as kubernetes,file (required)")
	fs.StringVar(&opts.Namespace, "namespace", "", "kubernetes: only this namespace (default: all)")
	fs.Var(&opts.ECSClusters, "ecs-cluster", "ecs: cluster name or ARN; repeat for more (default: every cluster in AWS_REGION)")
	fs.StringVar(&opts.ImagesFile, "images-file", "", "file: one image or dir: entry per line")
	fs.StringVar(&opts.PolicyPath, "policy", "", "policy file")
	fs.StringVar(&opts.Exceptions, "exceptions", "", "exceptions file that applies to running images and directories")
	fs.StringVar(&opts.OutDir, "out", "scanproof-rescan", "working directory for the evidence files")
	fs.BoolVar(&opts.PDF, "pdf", false, "write a report.pdf for every image and directory")
	fs.BoolVar(&opts.PullMissing, "pull-missing", true, "pull and scan images that have no stored SBOM (directories are never pulled)")
	fs.StringVar(&when, "notify", string(notify.WhenViolation), "when to post one summary to chat: violation, always or never")
	fs.StringVar(&opts.TrivyBin, "trivy", "trivy", "path to the trivy binary")
	fs.StringVar(&opts.TypstBin, "typst", "typst", "path to the typst binary")
	fs.DurationVar(&opts.Timeout, "timeout", 30*time.Minute, "time limit for each image or directory")
	if err := fs.Parse(args); err != nil {
		return rescanOptions{}, err
	}
	if fs.NArg() > 0 {
		return rescanOptions{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	var err error
	if opts.Inventories, err = parseInventories(inventories); err != nil {
		return rescanOptions{}, err
	}
	if err := validateRescanOptions(opts); err != nil {
		return rescanOptions{}, err
	}
	if opts.Notify, err = notify.ParseWhen(when); err != nil {
		return rescanOptions{}, err
	}
	return opts, nil
}

// parseInventories reads "kubernetes", "file" or a list such as
// "kubernetes,file", dropping repeats.
func parseInventories(v string) ([]string, error) {
	if strings.TrimSpace(v) == "" {
		return nil, errors.New("--inventory is required (kubernetes, ecs or file, or a comma-separated list)")
	}
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		name := strings.TrimSpace(part)
		if !slices.Contains(knownInventories, name) {
			return nil, fmt.Errorf("unknown inventory %q (want kubernetes, ecs or file, or a comma-separated list such as kubernetes,file)", name)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

func validateRescanOptions(opts rescanOptions) error {
	switch {
	case opts.Store == "":
		return errors.New("--store is required")
	case slices.Contains(opts.Inventories, "file") && opts.ImagesFile == "":
		return errors.New("--inventory file needs --images-file")
	case opts.Timeout <= 0:
		return errors.New("--timeout must be greater than zero")
	}
	return nil
}

// inventorySources returns one source per inventory, in order. A source
// that cannot be set up (for example Kubernetes outside a cluster) is a
// failure; the others are still used.
func inventorySources(ctx context.Context, opts rescanOptions) (inventory.Combined, []inventory.Failure) {
	sources := inventory.Combined{}
	failures := []inventory.Failure{}
	if opts.ImagesFile != "" && !slices.Contains(opts.Inventories, "file") {
		failures = append(failures, inventory.Failure{Where: "--images-file",
			Err: errors.New("it is only read with --inventory file (for example --inventory kubernetes,file)")})
	}
	for _, name := range opts.Inventories {
		var s inventory.Source
		var err error
		switch name {
		case "kubernetes":
			s, err = inventory.InCluster(opts.Namespace)
		case "ecs":
			s, err = inventory.NewECS(ctx, opts.ECSClusters)
		default:
			s = inventory.File{Path: opts.ImagesFile}
		}
		if err != nil {
			failures = append(failures, inventory.Failure{Where: name + " inventory", Err: err})
			continue
		}
		sources = append(sources, inventory.NamedSource{Name: name, Source: s})
	}
	return sources, failures
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
	images, failures := listRunning(ctx, opts)
	if len(failures) == 0 {
		// Otherwise the images of the failed source are missing from the list.
		warnUnmatchedScopes(env, setup.excs, images)
	}
	outcomes := append(inventoryOutcomes(env, failures), rescanAll(ctx, opts, env, st, setup, images)...)
	sendRescanNotification(ctx, opts, env, outcomes)
	return finishRescan(env, outcomes, images)
}

// listRunning lists what runs, merged by digest, and the sources and lines
// that could not be read.
func listRunning(ctx context.Context, opts rescanOptions) ([]inventory.RunningImage, []inventory.Failure) {
	sources, failures := inventorySources(ctx, opts)
	found, more := sources.List(ctx)
	return inventory.Merge(found), append(failures, more...)
}

// inventoryOutcomes reports each inventory source or line that could not be
// read as a failed outcome, so the run still exits 2 and the chat lists it.
func inventoryOutcomes(env Env, failures []inventory.Failure) []rescanOutcome {
	out := make([]rescanOutcome, 0, len(failures))
	for _, f := range failures {
		fmt.Fprintf(env.Stderr, "scanproof: %s: %v\n", f.Where, f.Err)
		out = append(out, rescanOutcome{where: f.Where, err: f.Err})
	}
	return out
}

// finishRescan prints the totals and returns the exit code: 2 when anything
// could not be rescanned. Violations alone never fail a rescan.
func finishRescan(env Env, outcomes []rescanOutcome, images []inventory.RunningImage) int {
	done, failed := []inventory.RunningImage{}, 0
	for _, o := range outcomes {
		switch {
		case o.err != nil:
			failed++
		case o.where == "":
			done = append(done, o.image)
		}
	}
	fmt.Fprintf(env.Stdout, "ScanProof rescan: %s rescanned, %d failed, %s found\n",
		countPhrase(done, ""), failed, countPhrase(images, "running "))
	if failed > 0 {
		return ExitError
	}
	return ExitOK
}

// countPhrase counts images and directories: "2 running images",
// "1 directory" or "2 images and 1 directory".
func countPhrase(images []inventory.RunningImage, imageAdjective string) string {
	dirs := 0
	for _, img := range images {
		if img.Directory {
			dirs++
		}
	}
	imageCount := pluralize(len(images)-dirs, imageAdjective+"image", imageAdjective+"images")
	switch {
	case dirs == 0:
		return imageCount
	case dirs == len(images):
		return pluralize(dirs, "directory", "directories")
	}
	return imageCount + " and " + pluralize(dirs, "directory", "directories")
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
