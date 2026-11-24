package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
)

type scanOptions struct {
	Image        string
	PolicyPath   string
	Exceptions   string
	Mode         policy.Mode // empty means "use the policy file"
	OutDir       string
	PDF          bool
	Notify       notify.When
	TrivyResults string
	TrivyBin     string
	TypstBin     string
	Timeout      time.Duration
}

func parseScanOptions(args []string, stderr io.Writer) (scanOptions, error) {
	fs := flag.NewFlagSet("scanproof scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := scanOptions{}
	var mode, when string
	fs.StringVar(&opts.PolicyPath, "policy", "", "policy file (default: warn on fixable Critical vulnerabilities and secrets)")
	fs.StringVar(&opts.Exceptions, "exceptions", "", "exceptions file listing accepted findings")
	fs.StringVar(&mode, "mode", "", "warn or enforce; overrides the policy file")
	fs.StringVar(&opts.OutDir, "out", "scanproof-out", "directory for results.json, summary.md, report.pdf and manifest.json")
	fs.BoolVar(&opts.PDF, "pdf", true, "write report.pdf (needs typst)")
	fs.StringVar(&when, "notify", string(notify.WhenViolation), "when to send chat notifications: violation, always or never")
	fs.StringVar(&opts.TrivyResults, "trivy-results", "", "use an existing Trivy JSON report instead of running Trivy")
	fs.StringVar(&opts.TrivyBin, "trivy", "trivy", "path to the trivy binary")
	fs.StringVar(&opts.TypstBin, "typst", "typst", "path to the typst binary")
	fs.DurationVar(&opts.Timeout, "timeout", 30*time.Minute, "maximum time for the scan")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: scanproof scan [flags] IMAGE\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nChat notifications go to the webhooks in %s and %s.\n",
			notify.EnvDiscordWebhook, notify.EnvSlackWebhook)
	}

	if err := fs.Parse(args); err != nil {
		return scanOptions{}, err
	}

	switch rest := fs.Args(); {
	case len(rest) > 1:
		return scanOptions{}, fmt.Errorf("expected one image, got %d: %s", len(rest), strings.Join(rest, " "))
	case len(rest) == 1:
		opts.Image = rest[0]
	case opts.TrivyResults == "":
		return scanOptions{}, errors.New("an image reference is required (or --trivy-results)")
	}

	if opts.Timeout <= 0 {
		return scanOptions{}, fmt.Errorf("--timeout must be greater than zero, got %s", opts.Timeout)
	}
	if mode != "" {
		m, err := policy.ParseMode(mode)
		if err != nil {
			return scanOptions{}, err
		}
		opts.Mode = m
	}
	w, err := notify.ParseWhen(when)
	if err != nil {
		return scanOptions{}, err
	}
	opts.Notify = w
	return opts, nil
}
