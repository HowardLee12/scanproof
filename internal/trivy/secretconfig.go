package trivy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// allowRuleIDs are the built-in secret allow rules of Trivy 0.76.2. Each
// skips matching paths: tests, examples, vendor directories, system
// directories (usr/share, usr/include, usr/lib), locale directories,
// Markdown files, and the language directories of Node, Go, Python, Ruby
// and WordPress images. Trivy accepts unknown IDs silently, so the CI
// image job checks that these really switch the rules off.
var allowRuleIDs = []string{
	"tests", "examples", "vendor", "usr-dirs", "locale-dir", "markdown",
	"node.js", "golang", "python", "rubygems", "wordpress",
}

// absentSecretConfig names a file in dir that does not exist, so Trivy uses
// its built-in secret rules, allow rules included. Image scans use it: the
// allow rules keep operating system and language files out of every report.
func absentSecretConfig(dir string) (string, error) {
	suffix := strings.TrimPrefix(filepath.Base(dir), "scanproof-trivy-")
	return filepath.Join(dir, "scanproof-secret-"+suffix+".yaml"), nil
}

// noAllowRulesConfig writes a secret config that switches every built-in
// allow rule off. Directory scans use it, so tests, examples, Markdown and
// the other allow-listed paths are read for secrets too.
func noAllowRulesConfig(dir string) (string, error) {
	f, err := os.CreateTemp(dir, "scanproof-secret-*.yaml")
	if err != nil {
		return "", fmt.Errorf("write trivy secret config: %w", err)
	}
	defer f.Close()
	content := "disable-allow-rules:\n  - " + strings.Join(allowRuleIDs, "\n  - ") + "\n"
	if _, err := f.WriteString(content); err != nil {
		return "", fmt.Errorf("write trivy secret config: %w", err)
	}
	return f.Name(), nil
}
