package trivy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/stopped"
)

// maxStderr bounds how much of Trivy's stderr is copied into an error.
const maxStderr = 4096

type execFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// defaultTimeout matches the scan command's default.
const defaultTimeout = 30 * time.Minute

// allowedTrivyEnv lists the TRIVY_* variables passed through to Trivy. They
// cover registry login, caching and database mirrors. Every other TRIVY_*
// variable is dropped because it could hide findings (severity filters,
// ignore files, VEX, skipped paths) without leaving a trace in the evidence.
var allowedTrivyEnv = map[string]bool{
	"TRIVY_USERNAME":           true,
	"TRIVY_PASSWORD":           true,
	"TRIVY_REGISTRY_TOKEN":     true,
	"TRIVY_CACHE_DIR":          true,
	"TRIVY_DB_REPOSITORY":      true,
	"TRIVY_JAVA_DB_REPOSITORY": true,
	"TRIVY_INSECURE":           true,
	"TRIVY_PLATFORM":           true,
	"TRIVY_NO_PROGRESS":        true,
}

// Runner invokes the Trivy binary.
type Runner struct {
	Bin     string
	Timeout time.Duration
	// Platform selects one image of a multi-platform index, e.g. linux/arm64.
	Platform string
	exec     execFunc
}

// NewRunner returns a Runner that executes the Trivy binary at bin.
func NewRunner(bin string, timeout time.Duration) Runner {
	return Runner{Bin: bin, Timeout: timeout, exec: defaultExec}
}

// Scan is the outcome of one Trivy run.
type Scan struct {
	Result model.ScanResult
	// Raw is Trivy's own JSON report, kept so it can be converted to an SBOM.
	Raw []byte
}

// Scan scans one container image for vulnerabilities and secrets.
func (r Runner) Scan(ctx context.Context, image string) (Scan, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return Scan{}, errors.New("image reference is empty")
	}
	if strings.HasPrefix(image, "-") {
		return Scan{}, fmt.Errorf("image reference %q must not start with '-'", image)
	}

	extra := []string{}
	if r.Platform != "" {
		extra = append(extra, "--platform", r.Platform)
	}
	return r.scanArtifact(ctx, "image", image, extra, absentSecretConfig)
}

// ScanRootfs scans an installed directory tree for vulnerabilities and
// secrets. Trivy's rootfs mode finds installed packages: Python dist-info
// and egg-info metadata, Go binaries, jars and OS package databases. path
// must be absolute, so it can never be read as a flag.
func (r Runner) ScanRootfs(ctx context.Context, path string) (Scan, error) {
	if !filepath.IsAbs(strings.TrimSpace(path)) {
		return Scan{}, fmt.Errorf("directory %q must be an absolute path", path)
	}
	return r.scanArtifact(ctx, "rootfs", path, nil, noAllowRulesConfig)
}

// scanArtifact runs one `trivy image` or `trivy rootfs` scan with every
// package listed, which the SBOM for later rescans needs. A trivy-secret.yaml
// in the working directory could switch secret rules off, so the secret
// scanner's settings file is always pinned to a file in a fresh private
// directory, made by secretConfig. Its name is unique, because Trivy does
// not read a top-level file named like its secret config.
func (r Runner) scanArtifact(ctx context.Context, mode, target string, extra []string, secretConfig func(dir string) (string, error)) (Scan, error) {
	settings, err := os.MkdirTemp("", "scanproof-trivy-")
	if err != nil {
		return Scan{}, fmt.Errorf("create trivy settings directory: %w", err)
	}
	defer os.RemoveAll(settings)
	config, err := secretConfig(settings)
	if err != nil {
		return Scan{}, err
	}
	args := append([]string{mode, "--quiet", "--format", "json", "--scanners", "vuln,secret", "--list-all-pkgs",
		"--secret-config", config}, r.hardenedFlags()...)
	args = append(args, extra...)
	out, err := r.run(ctx, "during the Trivy scan", append(args, target)...)
	if err != nil {
		return Scan{}, fmt.Errorf("trivy scan of %s failed: %w", target, err)
	}
	res, err := Parse(bytes.NewReader(out))
	if err != nil {
		return Scan{}, err
	}
	return Scan{Result: r.withDatabaseInfo(ctx, res), Raw: out}, nil
}

// hardenedFlags ignore Trivy settings files in the working directory
// (trivy.yaml, .trivyignore) and set every filter explicitly, so the only
// way to accept a finding is a ScanProof exception with a reason and an
// expiry date. Scans that look for secrets also pin --secret-config (see
// scanArtifact); `trivy sbom` has no such flag.
func (r Runner) hardenedFlags() []string {
	return []string{
		"--config", os.DevNull,
		"--ignorefile", "",
		"--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--ignore-unfixed=false",
		"--timeout", r.timeout().String(),
	}
}

// timeout is the --timeout Trivy gets.
func (r Runner) timeout() time.Duration {
	if r.Timeout <= 0 {
		return defaultTimeout
	}
	return r.Timeout
}

// ScanSBOM checks a stored CycloneDX SBOM against today's vulnerability
// database. It finds new vulnerabilities without pulling the image, but it
// cannot look for secrets. The caller sets the image reference and digest.
func (r Runner) ScanSBOM(ctx context.Context, sbom []byte) (Scan, error) {
	dir, err := os.MkdirTemp("", "scanproof-rescan-")
	if err != nil {
		return Scan{}, fmt.Errorf("create rescan work directory: %w", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(path, sbom, 0o600); err != nil {
		return Scan{}, fmt.Errorf("write SBOM: %w", err)
	}
	args := append([]string{"sbom", "--quiet", "--format", "json", "--scanners", "vuln"}, r.hardenedFlags()...)
	out, err := r.run(ctx, "during the Trivy SBOM scan", append(args, path)...)
	if err != nil {
		return Scan{}, fmt.Errorf("trivy SBOM scan failed: %w", err)
	}
	res, err := Parse(bytes.NewReader(out))
	if err != nil {
		return Scan{}, err
	}
	res.Image.Reference = ""
	return Scan{Result: r.withDatabaseInfo(ctx, res), Raw: out}, nil
}

// withDatabaseInfo adds the vulnerability database time. The time makes the
// evidence reproducible, but failing to read it must not discard a scan.
func (r Runner) withDatabaseInfo(ctx context.Context, res model.ScanResult) model.ScanResult {
	verOut, err := r.exec(ctx, r.Bin, "version", "--format", "json")
	if err != nil {
		return res
	}
	info, err := ParseVersion(bytes.NewReader(verOut))
	if err != nil {
		return res
	}
	res.Scanner = model.Scanner{
		Name:        res.Scanner.Name,
		Version:     firstNonEmpty(res.Scanner.Version, info.Version),
		DBUpdatedAt: info.DBUpdatedAt,
		Imported:    res.Scanner.Imported,
	}
	return res
}

// SBOM converts a raw Trivy JSON report into a CycloneDX SBOM. Rescans can
// then check the SBOM against a newer vulnerability database without pulling
// the image again.
func (r Runner) SBOM(ctx context.Context, raw []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "scanproof-sbom-")
	if err != nil {
		return nil, fmt.Errorf("create SBOM work directory: %w", err)
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "trivy.json")
	out := filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		return nil, fmt.Errorf("write trivy report: %w", err)
	}
	args := []string{"convert", "--config", os.DevNull, "--timeout", r.timeout().String(), "--format", "cyclonedx", "--output", out, in}
	if _, err := r.run(ctx, "during the SBOM conversion", args...); err != nil {
		return nil, fmt.Errorf("convert trivy report to an SBOM: %w", err)
	}
	sbom, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}
	return sbom, nil
}

// run runs Trivy for one step. If Trivy was killed because the scan's
// context ended, or reached its own --timeout (it then names whatever file
// it was reading), the error says so and names the step, instead of
// blaming the exit status or that file. Trivy's message stays the cause.
func (r Runner) run(ctx context.Context, phase string, args ...string) ([]byte, error) {
	start := time.Now()
	out, err := r.exec(ctx, r.Bin, args...)
	if err == nil {
		return out, nil
	}
	if stopped.Is(err) {
		return nil, stopped.InPhase(err, phase)
	}
	if r.reachedOwnTimeout(start, err) {
		return nil, &stopped.Error{Phase: phase, Err: fmt.Errorf("%w: %w", context.DeadlineExceeded, err)}
	}
	return nil, err
}

// reachedOwnTimeout reports whether Trivy stopped at its --timeout: it says
// "context deadline exceeded" and has run for at least that long. A
// download that times out earlier is Trivy's own failure.
func (r Runner) reachedOwnTimeout(start time.Time, err error) bool {
	return time.Since(start) >= r.timeout() && strings.Contains(err.Error(), "context deadline exceeded")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func defaultExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := stopped.Command(ctx, name, args...)
	cmd.Env = safeEnviron(os.Environ())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stop := cmd.Stopped(err); stop != nil {
			return nil, stop
		}
		return nil, fmt.Errorf("%w: %s", err, tail(stderr.String(), maxStderr))
	}
	return stdout.Bytes(), nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// safeEnviron removes TRIVY_* variables that are not in allowedTrivyEnv.
func safeEnviron(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "TRIVY_") && !allowedTrivyEnv[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}
