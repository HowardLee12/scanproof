package trivy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

// Scan scans one container image for vulnerabilities and secrets.
func (r Runner) Scan(ctx context.Context, image string) (model.ScanResult, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return model.ScanResult{}, errors.New("image reference is empty")
	}
	if strings.HasPrefix(image, "-") {
		return model.ScanResult{}, fmt.Errorf("image reference %q must not start with '-'", image)
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	// Settings files in the scanned repository (trivy.yaml, .trivyignore) are
	// ignored, and the filters are set explicitly, so the only way to accept a
	// finding is a ScanProof exception with a reason and an expiry date.
	out, err := r.exec(ctx, r.Bin, "image", "--quiet", "--format", "json",
		"--scanners", "vuln,secret",
		"--config", os.DevNull,
		"--ignorefile", "",
		"--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--ignore-unfixed=false",
		"--timeout", timeout.String(),
		image)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("trivy scan of %s failed: %w", image, err)
	}
	res, err := Parse(bytes.NewReader(out))
	if err != nil {
		return model.ScanResult{}, err
	}

	// The database time makes the evidence reproducible, but a failure to read
	// it must not throw away a completed scan.
	if verOut, verErr := r.exec(ctx, r.Bin, "version", "--format", "json"); verErr == nil {
		if info, parseErr := ParseVersion(bytes.NewReader(verOut)); parseErr == nil {
			res.Scanner = model.Scanner{
				Name:        res.Scanner.Name,
				Version:     firstNonEmpty(res.Scanner.Version, info.Version),
				DBUpdatedAt: info.DBUpdatedAt,
			}
		}
	}
	return res, nil
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
