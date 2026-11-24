// Package report turns an evaluated scan into evidence: a machine-readable
// results.json, a Markdown summary for CI, a PDF for auditors and a manifest
// of SHA-256 hashes.
package report

import (
	"sort"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
)

// SchemaVersion identifies the layout of results.json.
const SchemaVersion = "scanproof/v1"

// Triggers record why a scan ran, so a period summary can tell build-time
// checks from daily rescans.
const (
	TriggerCI     = "ci"
	TriggerRescan = "rescan"
	TriggerManual = "manual"
)

// Tool identifies the program that produced the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SeverityCount summarises vulnerabilities of one severity.
type SeverityCount struct {
	Severity model.Severity `json:"severity"`
	Total    int            `json:"total"`
	Fixable  int            `json:"fixable"`
	Accepted int            `json:"accepted"`
}

// Summary holds the headline numbers of a report.
type Summary struct {
	Vulnerabilities []SeverityCount `json:"vulnerabilities"`
	Secrets         int             `json:"secrets"`
	SecretsAccepted int             `json:"secrets_accepted"`
	Violations      int             `json:"violations"`
}

// PolicyInfo records which rules were applied and their outcome.
type PolicyInfo struct {
	Mode         policy.Mode         `json:"mode"`
	Source       string              `json:"source"`
	SHA256       string              `json:"sha256,omitempty"`
	MinSeverity  model.Severity      `json:"min_severity"`
	FixableOnly  bool                `json:"fixable_only"`
	BlockSecrets bool                `json:"block_secrets"`
	Rules        []policy.RuleResult `json:"rules"`
}

// Exceptions groups exceptions by how they affected this scan.
type Exceptions struct {
	Applied []exception.Exception `json:"applied"`
	Expired []exception.Exception `json:"expired"`
	Unused  []exception.Exception `json:"unused"`
}

// Document is the content of results.json and the source of every other output.
type Document struct {
	Schema          string                        `json:"schema"`
	ReportID        string                        `json:"report_id"`
	GeneratedAt     time.Time                     `json:"generated_at"`
	Tool            Tool                          `json:"tool"`
	Trigger         string                        `json:"trigger"`
	Verdict         policy.Verdict                `json:"verdict"`
	Image           model.Image                   `json:"image"`
	Scanner         model.Scanner                 `json:"scanner"`
	ScannedAt       time.Time                     `json:"scanned_at"`
	Context         cicontext.Context             `json:"context"`
	Runtime         *Runtime                      `json:"runtime,omitempty"`
	Policy          PolicyInfo                    `json:"policy"`
	Summary         Summary                       `json:"summary"`
	Vulnerabilities []policy.VulnerabilityFinding `json:"vulnerabilities"`
	Secrets         []policy.SecretFinding        `json:"secrets"`
	Exceptions      Exceptions                    `json:"exceptions"`
}

// Runtime describes a rescan of a running image.
type Runtime struct {
	// Locations are where the image runs, e.g. "k8s gpu/vllm-0".
	Locations []string `json:"locations"`
	// Method is "sbom" when the stored SBOM was checked again, or "image"
	// when the image itself was pulled and scanned.
	Method string `json:"method"`
	// SBOMFrom is the report whose SBOM was used.
	SBOMFrom string `json:"sbom_from,omitempty"`
}

// Rescan methods.
const (
	MethodSBOM  = "sbom"
	MethodImage = "image"
)

// Input is everything Build needs.
type Input struct {
	ReportID     string
	GeneratedAt  time.Time
	Tool         Tool
	Trigger      string
	Result       model.ScanResult
	Evaluation   policy.Evaluation
	Policy       policy.Policy
	PolicySource policy.Source
	Context      cicontext.Context
	Runtime      *Runtime
}

// Build assembles the report document. Findings are sorted with the most
// severe first; the inputs are not modified.
func Build(in Input) Document {
	ev := in.Evaluation
	return Document{
		Schema:      SchemaVersion,
		ReportID:    in.ReportID,
		GeneratedAt: in.GeneratedAt.UTC(),
		Tool:        in.Tool,
		Trigger:     in.Trigger,
		Verdict:     ev.Verdict,
		Image:       in.Result.Image,
		Scanner:     in.Result.Scanner,
		ScannedAt:   in.Result.ScannedAt,
		Context:     in.Context,
		Runtime:     in.Runtime,
		Policy: PolicyInfo{
			Mode:         in.Policy.Mode,
			Source:       in.PolicySource.Label(),
			SHA256:       in.PolicySource.SHA256,
			MinSeverity:  in.Policy.MinSeverity,
			FixableOnly:  in.Policy.FixableOnly,
			BlockSecrets: in.Policy.BlockSecrets,
			Rules:        orEmpty(ev.Rules),
		},
		Summary:         summarize(ev),
		Vulnerabilities: sortedVulnerabilities(ev.Vulnerabilities),
		Secrets:         orEmpty(ev.Secrets),
		Exceptions: Exceptions{
			Applied: orEmpty(ev.Applied),
			Expired: orEmpty(ev.Expired),
			Unused:  orEmpty(ev.Unused),
		},
	}
}

// orEmpty makes nil slices encode as [] rather than null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func summarize(ev policy.Evaluation) Summary {
	bySeverity := map[model.Severity]SeverityCount{}
	violations := 0
	for _, f := range ev.Vulnerabilities {
		c := bySeverity[f.Severity]
		c.Total++
		if f.Fixable() {
			c.Fixable++
		}
		if f.Accepted() {
			c.Accepted++
		}
		bySeverity[f.Severity] = c
		if f.Violation {
			violations++
		}
	}

	counts := make([]SeverityCount, 0, len(model.AllSeverities()))
	for _, sev := range model.AllSeverities() {
		c := bySeverity[sev]
		c.Severity = sev
		counts = append(counts, c)
	}

	s := Summary{Vulnerabilities: counts, Secrets: len(ev.Secrets)}
	for _, f := range ev.Secrets {
		if f.Accepted() {
			s.SecretsAccepted++
		}
		if f.Violation {
			violations++
		}
	}
	s.Violations = violations
	return s
}

func sortedVulnerabilities(in []policy.VulnerabilityFinding) []policy.VulnerabilityFinding {
	out := append([]policy.VulnerabilityFinding{}, in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Violation != b.Violation {
			return a.Violation
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.ID < b.ID
	})
	return out
}

// Count returns the summary entry for one severity.
func (s Summary) Count(sev model.Severity) SeverityCount {
	for _, c := range s.Vulnerabilities {
		if c.Severity == sev {
			return c
		}
	}
	return SeverityCount{Severity: sev}
}
