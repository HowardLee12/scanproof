// Package notify sends a short scan summary to chat webhooks (Discord and
// Slack). Webhook URLs contain credentials, so they come from environment
// variables and never appear in logs or errors.
package notify

import (
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

// maxListedViolations keeps chat messages short.
const maxListedViolations = 5

// When controls which results trigger a notification.
type When string

const (
	WhenViolation When = "violation"
	WhenAlways    When = "always"
	WhenNever     When = "never"
)

// ParseWhen accepts violation, always or never.
func ParseWhen(s string) (When, error) {
	switch w := When(strings.ToLower(strings.TrimSpace(s))); w {
	case WhenViolation, WhenAlways, WhenNever:
		return w, nil
	}
	return "", fmt.Errorf("unknown notify setting %q (want violation, always or never)", s)
}

// ShouldNotify reports whether a scan with verdict v should be announced.
func ShouldNotify(w When, v policy.Verdict) bool {
	switch w {
	case WhenAlways:
		return true
	case WhenViolation:
		return v != policy.VerdictPass
	default:
		return false
	}
}

// Field is a short labelled value.
type Field struct {
	Name  string
	Value string
}

// Message is the chat-platform-neutral content of a notification.
type Message struct {
	Verdict        policy.Verdict
	Title          string
	Summary        string
	Fields         []Field
	Violations     []string
	MoreViolations int
	URL            string
	ReportID       string
}

// NewMessage summarises a report for chat.
func NewMessage(doc report.Document) Message {
	violations, more := violationLines(doc.Vulnerabilities)
	return Message{
		Verdict:        doc.Verdict,
		Title:          fmt.Sprintf("ScanProof %s: %s", doc.Verdict, report.ArtifactLabel(doc)),
		Summary:        summaryLine(doc),
		Fields:         fields(doc),
		Violations:     violations,
		MoreViolations: more,
		URL:            doc.Context.RunURL,
		ReportID:       doc.ReportID,
	}
}

func summaryLine(doc report.Document) string {
	count := fmt.Sprintf("%d policy violations", doc.Summary.Violations)
	if doc.Summary.Violations == 1 {
		count = "1 policy violation"
	}
	return fmt.Sprintf("%s · %s mode", count, doc.Policy.Mode)
}

func fields(doc report.Document) []Field {
	out := make([]Field, 0, 7)
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh} {
		c := doc.Summary.Count(sev)
		out = append(out, Field{Name: sev.String(), Value: fmt.Sprintf("%d (%d fixable)", c.Total, c.Fixable)})
	}
	out = append(out, Field{Name: "Secrets", Value: fmt.Sprintf("%d", doc.Summary.Secrets)})
	if doc.Context.Repository != "" {
		out = append(out, Field{Name: "Repository", Value: doc.Context.Repository})
	}
	if doc.Context.Branch != "" {
		out = append(out, Field{Name: "Branch", Value: doc.Context.Branch})
	}
	return append(out, directoryFields(doc)...)
}

// directoryFields identify a scanned directory: where it was scanned and
// its tree digest, which the rescan inventory lists it by.
func directoryFields(doc report.Document) []Field {
	if !doc.IsDirectory() {
		return nil
	}
	out := []Field{}
	if doc.Directory != nil && doc.Directory.Path != "" {
		out = append(out, Field{Name: "Path", Value: doc.Directory.Path})
	}
	return append(out, Field{Name: "Tree digest", Value: shortDigest(doc.Image.Digest)})
}

// shortDigest keeps the algorithm and the first 12 hex characters.
func shortDigest(d string) string {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) <= 12 {
		return d
	}
	return algo + ":" + hex[:12] + "…"
}

func violationLines(findings []policy.VulnerabilityFinding) ([]string, int) {
	lines := make([]string, 0, maxListedViolations)
	total := 0
	for _, f := range findings {
		if !f.Violation {
			continue
		}
		total++
		if len(lines) < maxListedViolations {
			line := fmt.Sprintf("%s %s in %s", f.Severity, f.ID, f.Package)
			if f.FixedVersion != "" {
				line += fmt.Sprintf(" (fixed in %s)", f.FixedVersion)
			}
			lines = append(lines, line)
		}
	}
	return lines, total - len(lines)
}

// truncate shortens s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
