package policy

import (
	"fmt"
	"time"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
)

// Verdict is the overall outcome of a scan.
type Verdict string

const (
	VerdictPass Verdict = "PASS"
	VerdictWarn Verdict = "WARN"
	VerdictFail Verdict = "FAIL"
)

// VulnerabilityFinding is a vulnerability after exceptions and rules are applied.
type VulnerabilityFinding struct {
	model.Vulnerability
	ExceptionID string `json:"exception_id,omitempty"`
	Violation   bool   `json:"violation"`
}

// Accepted reports whether an active exception covers the finding.
func (f VulnerabilityFinding) Accepted() bool { return f.ExceptionID != "" }

// SecretFinding is a secret after exceptions and rules are applied.
type SecretFinding struct {
	model.Secret
	ExceptionID string `json:"exception_id,omitempty"`
	Violation   bool   `json:"violation"`
}

// Accepted reports whether an active exception covers the finding.
func (f SecretFinding) Accepted() bool { return f.ExceptionID != "" }

// MalwareFinding is a malware detection after exceptions and rules are applied.
type MalwareFinding struct {
	model.MalwareDetection
	ExceptionID string `json:"exception_id,omitempty"`
	Violation   bool   `json:"violation"`
}

// Accepted reports whether an active exception covers the finding.
func (f MalwareFinding) Accepted() bool { return f.ExceptionID != "" }

// RuleResult is the outcome of one policy rule.
type RuleResult struct {
	Name      string `json:"name"`
	Threshold string `json:"threshold"`
	Found     int    `json:"found"`
	Passed    bool   `json:"passed"`
}

// Evaluation is the full outcome of applying a policy to a scan.
type Evaluation struct {
	Vulnerabilities []VulnerabilityFinding
	Secrets         []SecretFinding
	// Malware is nil when no malware scan ran.
	Malware []MalwareFinding
	// Applied are active exceptions that accepted at least one finding.
	Applied []exception.Exception
	// Expired are exceptions that would have matched but have expired.
	Expired []exception.Exception
	// Unused are active exceptions that matched nothing in this image.
	Unused  []exception.Exception
	Rules   []RuleResult
	Verdict Verdict
}

// Evaluate applies exceptions and the policy to a scan result. It does not
// modify its inputs.
func Evaluate(res model.ScanResult, p Policy, excs []exception.Exception, now time.Time) Evaluation {
	tracker := newExceptionTracker(excs, now)

	vulns := make([]VulnerabilityFinding, 0, len(res.Vulnerabilities))
	vulnViolations := 0
	for _, v := range res.Vulnerabilities {
		id := tracker.matchVulnerability(v)
		violation := id == "" && v.Severity >= p.MinSeverity && (!p.FixableOnly || v.Fixable())
		if violation {
			vulnViolations++
		}
		vulns = append(vulns, VulnerabilityFinding{Vulnerability: v, ExceptionID: id, Violation: violation})
	}

	secrets := make([]SecretFinding, 0, len(res.Secrets))
	secretViolations := 0
	for _, s := range res.Secrets {
		id := tracker.matchSecret(s)
		violation := p.BlockSecrets && id == ""
		if violation {
			secretViolations++
		}
		secrets = append(secrets, SecretFinding{Secret: s, ExceptionID: id, Violation: violation})
	}

	var malware []MalwareFinding
	malwareViolations := 0
	if res.Malware != nil {
		malware = make([]MalwareFinding, 0, len(res.Malware.Detections))
		for _, d := range res.Malware.Detections {
			id := tracker.match(func(ex exception.Exception) bool { return ex.MatchesMalware(d) })
			violation := p.BlockMalware && id == ""
			if violation {
				malwareViolations++
			}
			malware = append(malware, MalwareFinding{MalwareDetection: d, ExceptionID: id, Violation: violation})
		}
	}

	rules := []RuleResult{newRule(vulnerabilityRuleName(p), vulnViolations)}
	if p.BlockSecrets {
		rules = append(rules, newRule("No embedded secrets", secretViolations))
	}
	if res.Malware != nil && p.BlockMalware {
		rules = append(rules, newRule("No malware detections", malwareViolations))
	}
	unscanned := 0
	if res.Malware != nil && p.BlockUnscanned {
		unscanned = len(res.Malware.Skipped)
		rules = append(rules, newRule("Every file scanned for malware", unscanned))
	}

	applied, expired, unused := tracker.summary()
	return Evaluation{
		Vulnerabilities: vulns,
		Secrets:         secrets,
		Malware:         malware,
		Applied:         applied,
		Expired:         expired,
		Unused:          unused,
		Rules:           rules,
		Verdict:         verdict(p.Mode, vulnViolations+secretViolations+malwareViolations+unscanned),
	}
}

func newRule(name string, found int) RuleResult {
	return RuleResult{Name: name, Threshold: "0 allowed", Found: found, Passed: found == 0}
}

func vulnerabilityRuleName(p Policy) string {
	levels := p.MinSeverity.String()
	if p.MinSeverity < model.SeverityCritical {
		levels = fmt.Sprintf("%s or %s", p.MinSeverity, model.SeverityCritical)
		if p.MinSeverity < model.SeverityHigh {
			levels = fmt.Sprintf("%s or higher", p.MinSeverity)
		}
	}
	name := fmt.Sprintf("No open %s vulnerabilities", levels)
	if p.FixableOnly {
		name += " with a fix available"
	}
	return name
}

func verdict(mode Mode, violations int) Verdict {
	switch {
	case violations == 0:
		return VerdictPass
	case mode == ModeEnforce:
		return VerdictFail
	default:
		return VerdictWarn
	}
}

// exceptionTracker remembers which exceptions matched, so the report can list
// applied, expired and unused exceptions.
type exceptionTracker struct {
	list    []exception.Exception
	now     time.Time
	used    map[string]bool
	expired map[string]bool
}

func newExceptionTracker(list []exception.Exception, now time.Time) *exceptionTracker {
	return &exceptionTracker{list: list, now: now, used: map[string]bool{}, expired: map[string]bool{}}
}

func (t *exceptionTracker) match(matches func(exception.Exception) bool) string {
	for _, ex := range t.list {
		if !matches(ex) {
			continue
		}
		if ex.Active(t.now) {
			t.used[ex.ID] = true
			return ex.ID
		}
		t.expired[ex.ID] = true
	}
	return ""
}

func (t *exceptionTracker) matchVulnerability(v model.Vulnerability) string {
	return t.match(func(ex exception.Exception) bool { return ex.MatchesVulnerability(v) })
}

func (t *exceptionTracker) matchSecret(s model.Secret) string {
	return t.match(func(ex exception.Exception) bool { return ex.MatchesSecret(s) })
}

func (t *exceptionTracker) summary() (applied, expired, unused []exception.Exception) {
	for _, ex := range t.list {
		switch {
		case t.used[ex.ID]:
			applied = append(applied, ex)
		case t.expired[ex.ID]:
			expired = append(expired, ex)
		case ex.Active(t.now):
			unused = append(unused, ex)
		}
	}
	return applied, expired, unused
}
