// Package policy decides which findings count as violations and whether a
// scan passes.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/HowardLee12/scanproof/internal/model"
)

// Mode controls what happens when a scan has violations.
type Mode string

const (
	// ModeWarn reports violations but lets the pipeline continue.
	ModeWarn Mode = "warn"
	// ModeEnforce fails the pipeline when there are violations.
	ModeEnforce Mode = "enforce"
)

// ParseMode accepts "warn" or "enforce", ignoring case.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeWarn:
		return ModeWarn, nil
	case ModeEnforce:
		return ModeEnforce, nil
	}
	return "", fmt.Errorf("unknown mode %q (want warn or enforce)", s)
}

// Policy is the set of rules a scan is evaluated against.
type Policy struct {
	Mode Mode
	// MinSeverity is the lowest severity that counts as a violation.
	MinSeverity model.Severity
	// FixableOnly limits violations to vulnerabilities that have a fix.
	FixableOnly bool
	// BlockSecrets makes every embedded secret a violation.
	BlockSecrets bool
}

// Default warns about fixable Critical vulnerabilities and any secret.
func Default() Policy {
	return Policy{
		Mode:         ModeWarn,
		MinSeverity:  model.SeverityCritical,
		FixableOnly:  true,
		BlockSecrets: true,
	}
}

// WithMode returns a copy of p with a different mode.
func (p Policy) WithMode(m Mode) Policy {
	p.Mode = m
	return p
}

type rawPolicy struct {
	Mode   *string `yaml:"mode"`
	FailOn struct {
		Severity    *string `yaml:"severity"`
		FixableOnly *bool   `yaml:"fixable_only"`
		Secrets     *bool   `yaml:"secrets"`
	} `yaml:"fail_on"`
}

// Parse reads a policy document. Fields that are not given keep their
// default values, and unknown keys are rejected.
func Parse(data []byte) (Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var raw rawPolicy
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}

	p := Default()
	if raw.Mode != nil {
		mode, err := ParseMode(*raw.Mode)
		if err != nil {
			return Policy{}, fmt.Errorf("policy mode: %w", err)
		}
		p.Mode = mode
	}
	if raw.FailOn.Severity != nil {
		sev, err := model.ParseSeverity(*raw.FailOn.Severity)
		if err != nil {
			return Policy{}, fmt.Errorf("policy fail_on.severity: %w", err)
		}
		p.MinSeverity = sev
	}
	if raw.FailOn.FixableOnly != nil {
		p.FixableOnly = *raw.FailOn.FixableOnly
	}
	if raw.FailOn.Secrets != nil {
		p.BlockSecrets = *raw.FailOn.Secrets
	}
	return p, nil
}

// Source identifies where a policy came from, so reports can show exactly
// which rules were applied.
type Source struct {
	Path   string
	SHA256 string
}

// BuiltinSource is the source of Default.
func BuiltinSource() Source {
	return Source{}
}

// Label is a human-readable name for the source.
func (s Source) Label() string {
	if s.Path == "" {
		return "built-in default"
	}
	return s.Path
}

// Load reads a policy file and records its path and SHA-256.
func Load(path string) (Policy, Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, Source{}, fmt.Errorf("read policy file %s: %w", path, err)
	}
	p, err := Parse(data)
	if err != nil {
		return Policy{}, Source{}, fmt.Errorf("policy file %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return p, Source{Path: path, SHA256: hex.EncodeToString(sum[:])}, nil
}
