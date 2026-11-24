package trivy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
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
	exec    execFunc
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

	args := append([]string{"image", "--quiet", "--format", "json", "--scanners", "vuln,secret", "--list-all-pkgs"},
		r.hardenedFlags()...)
	out, err := r.exec(ctx, r.Bin, append(args, image)...)
	if err != nil {
		return Scan{}, fmt.Errorf("trivy scan of %s failed: %w", image, err)
	}
	res, err := Parse(bytes.NewReader(out))
	if err != nil {
		return Scan{}, err
	}
	return Scan{Result: r.withDatabaseInfo(ctx, res), Raw: out}, nil
}

// hardenedFlags ignore settings files in the scanned repository (trivy.yaml,
// .trivyignore) and set every filter explicitly, so the only way to accept a
// finding is a ScanProof exception with a reason and an expiry date.
func (r Runner) hardenedFlags() []string {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return []string{
		"--config", os.DevNull,
		"--ignorefile", "",
		"--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--ignore-unfixed=false",
		"--timeout", timeout.String(),
	}
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
	out, err := r.exec(ctx, r.Bin, append(args, path)...)
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
	if _, err := r.exec(ctx, r.Bin, "convert", "--format", "cyclonedx", "--output", out, in); err != nil {
		return nil, fmt.Errorf("convert trivy report to an SBOM: %w", err)
	}
	sbom, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}
	return sbom, nil
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
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = safeEnviron(os.Environ())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
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
