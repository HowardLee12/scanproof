package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
	"github.com/HowardLee12/scanproof/internal/summary"
)

const (
	summaryJSON     = "summary.json"
	populationCSV   = "population.csv"
	summaryMarkdown = "summary.md"
	summaryPDF      = "summary.pdf"
	dateLayout      = "2006-01-02"
)

type reportOptions struct {
	Store        string
	From, To     time.Time
	LookbackDays int
	PolicyPath   string
	OutDir       string
	PDF          bool
	TypstBin     string
	Save         bool
}

func parseReportOptions(args []string, stderr io.Writer) (reportOptions, error) {
	fs := flag.NewFlagSet("scanproof report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := reportOptions{}
	var from, to string
	fs.StringVar(&opts.Store, "store", "", "where scans were stored: s3://bucket/prefix or file:///path (required)")
	fs.StringVar(&from, "from", "", "first day of the period, YYYY-MM-DD (required)")
	fs.StringVar(&to, "to", "", "last day of the period, YYYY-MM-DD (required)")
	fs.IntVar(&opts.LookbackDays, "lookback-days", 90, "days before the period to read, to date findings already open at the start")
	fs.StringVar(&opts.PolicyPath, "policy", "", "policy file with sla_days (default: 15/30/90 days for Critical/High/Medium)")
	fs.StringVar(&opts.OutDir, "out", "scanproof-summary", "directory for summary.json, population.csv, summary.md, summary.pdf and manifest.json")
	fs.BoolVar(&opts.PDF, "pdf", true, "write summary.pdf (needs typst)")
	fs.StringVar(&opts.TypstBin, "typst", "typst", "path to the typst binary")
	fs.BoolVar(&opts.Save, "save", false, "also save the summary to the store under summaries/")
	if err := fs.Parse(args); err != nil {
		return reportOptions{}, err
	}
	if fs.NArg() > 0 {
		return reportOptions{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if opts.Store == "" || from == "" || to == "" {
		return reportOptions{}, errors.New("--store, --from and --to are required")
	}
	var err error
	if opts.From, err = time.Parse(dateLayout, from); err != nil {
		return reportOptions{}, fmt.Errorf("--from %q must use the form YYYY-MM-DD", from)
	}
	if opts.To, err = time.Parse(dateLayout, to); err != nil {
		return reportOptions{}, fmt.Errorf("--to %q must use the form YYYY-MM-DD", to)
	}
	if opts.To.Before(opts.From) {
		return reportOptions{}, fmt.Errorf("--to %s is before --from %s", to, from)
	}
	if opts.LookbackDays < 0 {
		return reportOptions{}, errors.New("--lookback-days must be 0 or more")
	}
	return opts, nil
}

func runReport(ctx context.Context, args []string, env Env) int {
	opts, err := parseReportOptions(args, env.Stderr)
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
	pol := policy.Default()
	if opts.PolicyPath != "" {
		if pol, _, err = policy.Load(opts.PolicyPath); err != nil {
			return fail(env, err)
		}
	}

	period := summary.NewPeriod(opts.From, opts.To, opts.LookbackDays)
	loaded, err := summary.Load(ctx, st, period)
	if err != nil {
		return fail(env, err)
	}
	for _, loc := range loaded.Incomplete {
		fmt.Fprintf(env.Stderr, "scanproof: warning: skipping %s: upload did not finish (no manifest.json)\n", loc)
	}
	now := env.Now().UTC()
	id, err := summary.NewSummaryID(now)
	if err != nil {
		return fail(env, err)
	}
	s := summary.Build(summary.Input{
		ID: id, GeneratedAt: now, Tool: report.Tool{Name: "scanproof", Version: Version},
		Period: period, Policy: pol, StoreLocation: st.Location(""), Scans: loaded.Scans, Incomplete: loaded.Incomplete,
	})

	written, err := writeSummary(ctx, opts, env, s)
	if err != nil {
		return fail(env, err)
	}
	if opts.Save {
		prefix := store.SummaryPrefix(period.From, period.To, s.SummaryID)
		if err := uploadFiles(ctx, st, opts.OutDir, prefix, written); err != nil {
			return fail(env, err)
		}
		fmt.Fprintf(env.Stdout, "Saved to %s\n", st.Location(prefix))
	}
	c := s.Coverage
	fmt.Fprintf(env.Stdout, "ScanProof summary %s: %s to %s · %d scans · %d open past SLA · output in %s\n",
		s.SummaryID, s.Period.From, s.Period.To, c.Scans, len(s.Overdue), opts.OutDir)
	return ExitOK
}

func writeSummary(ctx context.Context, opts reportOptions, env Env, s summary.Summary) ([]string, error) {
	if err := os.MkdirAll(opts.OutDir, dirMode); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	path := func(name string) string { return filepath.Join(opts.OutDir, name) }
	if err := os.Remove(path(summaryPDF)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove old %s: %w", summaryPDF, err)
	}

	csv, err := summary.PopulationCSV(s.Population)
	if err != nil {
		return nil, err
	}
	if err := report.WriteFile(path(populationCSV), csv); err != nil {
		return nil, err
	}
	if err := report.WriteJSON(path(summaryJSON), s); err != nil {
		return nil, err
	}
	md := summary.Markdown(s)
	if err := report.WriteFile(path(summaryMarkdown), []byte(md)); err != nil {
		return nil, err
	}
	written := []string{summaryJSON, populationCSV, summaryMarkdown}

	if opts.PDF {
		hashes := map[string]string{}
		for _, name := range []string{populationCSV, summaryJSON} {
			if h, _, err := report.HashFile(path(name)); err == nil {
				hashes[name] = h
			}
		}
		renderer := report.NewPDFRenderer(opts.TypstBin)
		if !renderer.Available() {
			fmt.Fprintf(env.Stderr, "scanproof: warning: %s not found; skipping %s\n", opts.TypstBin, summaryPDF)
		} else if err := summary.RenderPDF(ctx, renderer, s, hashes, path(summaryPDF)); err != nil {
			fmt.Fprintf(env.Stderr, "scanproof: warning: %v; skipping %s\n", err, summaryPDF)
		} else {
			written = append(written, summaryPDF)
		}
	}

	manifest, err := report.BuildManifestFor(opts.OutDir, s.SummaryID, s.GeneratedAt, "", written)
	if err != nil {
		return nil, err
	}
	if err := report.WriteJSON(path(manifestFile), manifest); err != nil {
		return nil, err
	}
	writeGitHubStepSummary(env, env.Getenv("GITHUB_STEP_SUMMARY"), md)
	return append(written, manifestFile), nil
}
