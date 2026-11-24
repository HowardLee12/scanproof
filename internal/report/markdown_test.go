package report

import (
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
)

func TestMarkdownSummary(t *testing.T) {
	md := Markdown(sampleDocument(t))
	for _, want := range []string{
		"## ⚠️ ScanProof: WARN",
		"`alpine:3.18.0`",
		"2 policy violations",
		"| No open CRITICAL vulnerabilities with a fix available | 2 | ❌ |",
		"| CRITICAL | 3 | 3 | 1 |",
		"CVE-2022-48174",
		"EX-2026-004",
		"SR-20261124-7F3A9C",
		"Trivy 0.76.2",
		"warn mode",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("summary is missing %q", want)
		}
	}
}

func TestMarkdownPassHasNoViolationTable(t *testing.T) {
	doc := sampleDocument(t)
	doc.Verdict = policy.VerdictPass
	doc.Summary.Violations = 0
	doc.Vulnerabilities = nil
	md := Markdown(doc)
	if !strings.Contains(md, "## ✅ ScanProof: PASS") || strings.Contains(md, "### Violations") {
		t.Fatalf("unexpected pass summary:\n%s", md)
	}
}

func TestMarkdownFailHeading(t *testing.T) {
	doc := sampleDocument(t)
	doc.Verdict = policy.VerdictFail
	if !strings.Contains(Markdown(doc), "## ❌ ScanProof: FAIL") {
		t.Fatal("fail heading missing")
	}
}

func TestMarkdownListsSecretsWithoutContent(t *testing.T) {
	doc := sampleDocument(t)
	doc.Secrets = []policy.SecretFinding{{
		Secret:    model.Secret{RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Target: "app/config.ini", Line: 3},
		Violation: true,
	}}
	md := Markdown(doc)
	if !strings.Contains(md, "| aws-access-key-id | AWS Access Key ID | app/config.ini:3 | Violation |") {
		t.Fatalf("secret row missing:\n%s", md)
	}
}

func TestMarkdownEscapesTableCells(t *testing.T) {
	if got := cell("a|b\nc"); got != `a\|b c` {
		t.Fatalf("got %q", got)
	}
}

func TestMarkdownLimitsViolationRows(t *testing.T) {
	doc := sampleDocument(t)
	many := make([]policy.VulnerabilityFinding, 0, 30)
	for i := 0; i < 30; i++ {
		many = append(many, policy.VulnerabilityFinding{
			Vulnerability: model.Vulnerability{ID: "CVE-X", Severity: model.SeverityCritical},
			Violation:     true,
		})
	}
	doc.Vulnerabilities = many
	md := Markdown(doc)
	if strings.Count(md, "| CVE-X |") != maxMarkdownRows {
		t.Errorf("expected %d rows", maxMarkdownRows)
	}
	if !strings.Contains(md, "and 10 more in results.json") {
		t.Error("the summary should say how many rows were left out")
	}
}

func TestMarkdownExpiredAndUnusedExceptions(t *testing.T) {
	doc := sampleDocument(t)
	excs, _ := exception.Parse([]byte("exceptions:\n  - {id: EX-OLD, finding: CVE-1, reason: r, expires: 2026-01-01}\n  - {id: EX-IDLE, finding: CVE-2, reason: r, expires: 2027-01-01}\n"))
	doc.Exceptions.Expired = excs[:1]
	doc.Exceptions.Unused = excs[1:]
	md := Markdown(doc)
	if !strings.Contains(md, "Expired: EX-OLD") || !strings.Contains(md, "Unused: EX-IDLE") {
		t.Fatalf("exception lines missing:\n%s", md)
	}
}
