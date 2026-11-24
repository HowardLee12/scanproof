package report

import (
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/policy"
)

// maxMarkdownRows keeps the CI summary short; every finding is in results.json.
const maxMarkdownRows = 20

var verdictIcons = map[policy.Verdict]string{
	policy.VerdictPass: "✅",
	policy.VerdictWarn: "⚠️",
	policy.VerdictFail: "❌",
}

// Markdown renders a short summary for the CI job page.
func Markdown(doc Document) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s ScanProof: %s\n\n", verdictIcons[doc.Verdict], doc.Verdict)
	fmt.Fprintf(&b, "`%s` · %s · %s\n\n", doc.Image.Reference,
		plural(doc.Summary.Violations, "policy violation", "policy violations"), modeDescription(doc.Policy.Mode))

	writeRules(&b, doc.Policy.Rules)
	writeSeverityCounts(&b, doc.Summary)
	writeViolations(&b, doc.Vulnerabilities)
	writeSecrets(&b, doc.Secrets)
	writeExceptions(&b, doc.Exceptions)

	fmt.Fprintf(&b, "<sub>Report %s · digest `%s` · scanned %s with %s · policy: %s</sub>\n",
		doc.ReportID, doc.Image.Digest, formatTime(doc.ScannedAt), scannerDescription(doc), doc.Policy.Source)
	return b.String()
}

func writeRules(b *strings.Builder, rules []policy.RuleResult) {
	b.WriteString("| Rule | Found | Result |\n|---|---:|:---:|\n")
	for _, r := range rules {
		mark := "✅"
		if !r.Passed {
			mark = "❌"
		}
		fmt.Fprintf(b, "| %s | %d | %s |\n", cell(r.Name), r.Found, mark)
	}
	b.WriteString("\n")
}

func writeSeverityCounts(b *strings.Builder, s Summary) {
	b.WriteString("| Severity | Total | Fixable | Accepted |\n|---|---:|---:|---:|\n")
	for _, c := range s.Vulnerabilities {
		fmt.Fprintf(b, "| %s | %d | %d | %d |\n", c.Severity, c.Total, c.Fixable, c.Accepted)
	}
	fmt.Fprintf(b, "\nSecrets found: %d", s.Secrets)
	if s.SecretsAccepted > 0 {
		fmt.Fprintf(b, " (%d accepted)", s.SecretsAccepted)
	}
	b.WriteString("\n\n")
}

func writeViolations(b *strings.Builder, findings []policy.VulnerabilityFinding) {
	violations := make([]policy.VulnerabilityFinding, 0)
	for _, f := range findings {
		if f.Violation {
			violations = append(violations, f)
		}
	}
	if len(violations) == 0 {
		return
	}
	b.WriteString("### Violations\n\n| Severity | ID | Package | Installed | Fixed in |\n|---|---|---|---|---|\n")
	for i, f := range violations {
		if i == maxMarkdownRows {
			fmt.Fprintf(b, "\n_…and %d more in results.json_\n", len(violations)-maxMarkdownRows)
			break
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", f.Severity, cell(f.ID), cell(f.Package),
			cell(f.InstalledVersion), cell(f.FixedVersion))
	}
	b.WriteString("\n")
}

func writeSecrets(b *strings.Builder, secrets []policy.SecretFinding) {
	if len(secrets) == 0 {
		return
	}
	b.WriteString("### Secrets\n\nThe matched text is never stored or shown.\n\n")
	b.WriteString("| Rule | Title | Location | Status |\n|---|---|---|---|\n")
	for _, s := range secrets {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", cell(s.RuleID), cell(s.Title),
			cell(fmt.Sprintf("%s:%d", s.Target, s.Line)), findingStatus(s.ExceptionID, s.Violation))
	}
	b.WriteString("\n")
}

func writeExceptions(b *strings.Builder, e Exceptions) {
	if len(e.Applied)+len(e.Expired)+len(e.Unused) == 0 {
		return
	}
	b.WriteString("### Exceptions\n\n")
	for _, ex := range e.Applied {
		fmt.Fprintf(b, "- Applied: %s\n", describeException(ex, "expires"))
	}
	for _, ex := range e.Expired {
		fmt.Fprintf(b, "- Expired: %s\n", describeException(ex, "expired"))
	}
	for _, ex := range e.Unused {
		fmt.Fprintf(b, "- Unused: %s\n", describeException(ex, "expires"))
	}
	b.WriteString("\n")
}

func describeException(ex exception.Exception, verb string) string {
	return fmt.Sprintf("%s (%s, %s %s)", cell(ex.ID), cell(ex.Finding), verb, ex.Expires)
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.Join(strings.Fields(s), " ")
}
