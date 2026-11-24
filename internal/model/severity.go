// Package model holds the scanner-independent types that every other package
// works with. Scanner output is converted into these types once, so policy,
// reports and notifications never depend on a particular scanner's format.
package model

import (
	"fmt"
	"strings"
)

// Severity is ordered so that comparisons such as s >= SeverityHigh work.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:  "UNKNOWN",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

// ParseSeverity accepts the severity names used by Trivy, ignoring case and
// surrounding whitespace.
func ParseSeverity(s string) (Severity, error) {
	normalized := strings.ToUpper(strings.TrimSpace(s))
	for sev, name := range severityNames {
		if name == normalized {
			return sev, nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity %q (want CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN)", s)
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return severityNames[SeverityUnknown]
}

// MarshalText makes severities appear as their names in JSON and YAML.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText is the inverse of MarshalText.
func (s *Severity) UnmarshalText(text []byte) error {
	parsed, err := ParseSeverity(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// AllSeverities lists severities from most to least severe, for reports.
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown}
}
