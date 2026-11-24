package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
)

type scanOptions struct {
	Image        string
	Dir          dirOptions
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
	Platform     string
	Malware      malwareOptions
}

// dirOptions describe a directory scan (scan --dir).
type dirOptions struct {
	Enabled bool
	Path    string
	Name    string
	Version string
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

// imageOnlyFlags make no sense for a directory and are refused with --dir.
var imageOnlyFlags = []string{"platform", "docker-daemon", "trivy-results"}

const scanUsage = `Usage:
  scanproof scan [flags] IMAGE
  scanproof scan [flags] --trivy-results FILE
  scanproof scan --dir --name NAME [--version VERSION] [flags] PATH

Flags:
`

func parseScanOptions(args []string, stderr io.Writer) (scanOptions, error) {
	opts := scanOptions{}
	var mode, when string
	fs := scanFlagSet(stderr, &opts, &mode, &when)
	if err := fs.Parse(args); err != nil {
		return scanOptions{}, err
	}
	opts, err := withTarget(opts, fs.Args(), setFlags(fs))
	if err != nil {
		return scanOptions{}, err
	}
	if err := validateScanOptions(opts); err != nil {
		return scanOptions{}, err
	}
	if mode != "" {
		if opts.Mode, err = policy.ParseMode(mode); err != nil {
			return scanOptions{}, err
		}
	}
	if opts.Notify, err = notify.ParseWhen(when); err != nil {
		return scanOptions{}, err
	}
	// An imported report may list only vulnerable packages, so an SBOM built
	// from it would make later rescans miss new vulnerabilities.
	if opts.TrivyResults != "" {
		opts.SBOM = false
	}
	return opts, nil
}

func scanFlagSet(stderr io.Writer, opts *scanOptions, mode, when *string) *flag.FlagSet {
	fs := flag.NewFlagSet("scanproof scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&opts.Dir.Enabled, "dir", false, "scan the directory PATH instead of an image (needs --name)")
	fs.StringVar(&opts.Dir.Name, "name", "", "with --dir: the name the directory is tracked by, e.g. acme-vllm")
	fs.StringVar(&opts.Dir.Version, "version", "", "with --dir: the version of the software in the directory (optional)")
	fs.StringVar(&opts.PolicyPath, "policy", "", "policy file (default: warn on fixable Critical vulnerabilities and secrets)")
	fs.StringVar(&opts.Exceptions, "exceptions", "", "exceptions file listing accepted findings")
	fs.StringVar(mode, "mode", "", "warn or enforce; overrides the policy file")
	fs.StringVar(&opts.OutDir, "out", "scanproof-out", "directory for results.json, summary.md, report.pdf and manifest.json")
	fs.BoolVar(&opts.PDF, "pdf", true, "write report.pdf (needs typst)")
	fs.BoolVar(&opts.SBOM, "sbom", true, "write sbom.cdx.json, used by later rescans (needs trivy)")
	fs.StringVar(&opts.Store, "store", "", "upload the evidence to s3://bucket/prefix or file:///path")
	fs.StringVar(when, "notify", string(notify.WhenViolation), "when to send chat notifications: violation, always or never")
	fs.StringVar(&opts.TrivyResults, "trivy-results", "", "use an existing Trivy JSON report instead of running Trivy")
	fs.StringVar(&opts.TrivyBin, "trivy", "trivy", "path to the trivy binary")
	fs.StringVar(&opts.TypstBin, "typst", "typst", "path to the typst binary")
	fs.DurationVar(&opts.Timeout, "timeout", 30*time.Minute, "maximum time for the whole scan")
	fs.StringVar(&opts.Platform, "platform", "", "image platform for multi-platform images, e.g. linux/arm64 (default: this machine's)")
	defineMalwareFlags(fs, &opts.Malware)
	fs.Usage = func() {
		fmt.Fprint(stderr, scanUsage)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nChat notifications go to the webhooks in %s and %s.\n",
			notify.EnvDiscordWebhook, notify.EnvSlackWebhook)
	}
	return fs
}

func defineMalwareFlags(fs *flag.FlagSet, m *malwareOptions) {
	fs.BoolVar(&m.Enabled, "malware", false, "also scan every file in the image or directory for malware (needs clamscan)")
	fs.StringVar(&m.ClamscanBin, "clamscan", "clamscan", "path to the clamscan binary")
	fs.StringVar(&m.ClamAVDB, "clamav-db", "", "ClamAV signature directory (default: clamscan's own)")
	fs.StringVar(&m.YaraRules, "yara-rules", "", "YARA rule file or directory; enables YARA")
	fs.StringVar(&m.YaraBin, "yara", "yara", "path to the yara binary")
	fs.Int64Var(&m.MaxFileMB, "malware-max-file-mb", 512, "skip (and list) files larger than this many MB")
	fs.StringVar(&m.WorkDir, "malware-workdir", "", "where files are unpacked for the malware scan; needs room for the largest image layer, or about 1 GB plus the largest file for a directory")
	fs.BoolVar(&m.DockerDaemon, "docker-daemon", true, "look for the image in the local Docker daemon before the registry")
	fs.BoolVar(&m.Update, "clamav-update", false, "run freshclam before the malware scan (mind ClamAV's download limits)")
	fs.StringVar(&m.FreshclamBin, "freshclam", "freshclam", "path to the freshclam binary")
}

// setFlags returns the names of the flags given on the command line.
func setFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// withTarget sets the image or the directory to scan from the arguments.
func withTarget(opts scanOptions, rest []string, set map[string]bool) (scanOptions, error) {
	if opts.Dir.Enabled {
		return withDirectory(opts, rest, set)
	}
	if set["name"] || set["version"] {
		return scanOptions{}, errors.New("--name and --version describe a directory; use them with --dir")
	}
	switch {
	case len(rest) > 1:
		return scanOptions{}, fmt.Errorf("expected one image, got %d: %s", len(rest), strings.Join(rest, " "))
	case len(rest) == 1:
		opts.Image = rest[0]
	case opts.TrivyResults == "":
		return scanOptions{}, errors.New("an image reference is required (or --trivy-results)")
	}
	return opts, nil
}

func withDirectory(opts scanOptions, rest []string, set map[string]bool) (scanOptions, error) {
	for _, name := range imageOnlyFlags {
		if set[name] {
			return scanOptions{}, fmt.Errorf("--%s cannot be used with --dir: it only applies to images", name)
		}
	}
	if len(rest) != 1 {
		return scanOptions{}, fmt.Errorf("--dir needs exactly one directory path, got %d", len(rest))
	}
	if opts.Dir.Name == "" {
		return scanOptions{}, errors.New("--dir needs --name, the name the directory is tracked by (for example --name acme-vllm)")
	}
	if err := model.ValidateDirectoryName(opts.Dir.Name); err != nil {
		return scanOptions{}, err
	}
	if opts.Dir.Version != "" {
		if err := model.ValidateDirectoryVersion(opts.Dir.Version); err != nil {
			return scanOptions{}, err
		}
	}
	opts.Dir.Path = rest[0]
	return opts, nil
}

func validateScanOptions(opts scanOptions) error {
	if opts.Malware.Enabled && opts.Image == "" && !opts.Dir.Enabled {
		return errors.New("--malware needs the image reference, even with --trivy-results")
	}
	if opts.Malware.MaxFileMB <= 0 || opts.Malware.MaxFileMB > 4000 {
		return errors.New("--malware-max-file-mb must be between 1 and 4000 (ClamAV's limit)")
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("--timeout must be greater than zero, got %s", opts.Timeout)
	}
	return nil
}
