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
	SBOM         bool
	Store        string
	Notify       notify.When
	TrivyResults string
	TrivyBin     string
	TypstBin     string
	Timeout      time.Duration
	Malware      malwareOptions
}

type malwareOptions struct {
	Enabled      bool
	ClamscanBin  string
	ClamAVDB     string
	YaraRules    string
	YaraBin      string
	MaxFileMB    int64
	WorkDir      string
	DockerDaemon bool
	Update       bool
	FreshclamBin string
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
	fs.BoolVar(&opts.SBOM, "sbom", true, "write sbom.cdx.json, used by later rescans (needs trivy)")
	fs.StringVar(&opts.Store, "store", "", "upload the evidence to s3://bucket/prefix or file:///path")
	fs.StringVar(&when, "notify", string(notify.WhenViolation), "when to send chat notifications: violation, always or never")
	fs.StringVar(&opts.TrivyResults, "trivy-results", "", "use an existing Trivy JSON report instead of running Trivy")
	fs.StringVar(&opts.TrivyBin, "trivy", "trivy", "path to the trivy binary")
	fs.StringVar(&opts.TypstBin, "typst", "typst", "path to the typst binary")
	fs.DurationVar(&opts.Timeout, "timeout", 30*time.Minute, "maximum time for the scan")
	fs.BoolVar(&opts.Malware.Enabled, "malware", false, "also scan every file in the image for malware (needs clamscan)")
	fs.StringVar(&opts.Malware.ClamscanBin, "clamscan", "clamscan", "path to the clamscan binary")
	fs.StringVar(&opts.Malware.ClamAVDB, "clamav-db", "", "ClamAV signature directory (default: clamscan's own)")
	fs.StringVar(&opts.Malware.YaraRules, "yara-rules", "", "YARA rule file or directory; enables YARA")
	fs.StringVar(&opts.Malware.YaraBin, "yara", "yara", "path to the yara binary")
	fs.Int64Var(&opts.Malware.MaxFileMB, "malware-max-file-mb", 512, "skip (and list) files larger than this many MB")
	fs.StringVar(&opts.Malware.WorkDir, "malware-workdir", "", "where to unpack the image for the malware scan; needs room for the whole image")
	fs.BoolVar(&opts.Malware.DockerDaemon, "docker-daemon", true, "look for the image in the local Docker daemon before the registry")
	fs.BoolVar(&opts.Malware.Update, "clamav-update", false, "run freshclam before the malware scan (mind ClamAV's download limits)")
	fs.StringVar(&opts.Malware.FreshclamBin, "freshclam", "freshclam", "path to the freshclam binary")
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

	if opts.Malware.Enabled && opts.Image == "" {
		return scanOptions{}, errors.New("--malware needs the image reference, even with --trivy-results")
	}
	if opts.Malware.MaxFileMB <= 0 || opts.Malware.MaxFileMB > 4000 {
		return scanOptions{}, errors.New("--malware-max-file-mb must be between 1 and 4000 (ClamAV's limit)")
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
