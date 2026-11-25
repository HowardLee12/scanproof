package report

import (
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
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
	fmt.Fprintf(&b, "%s · %s · %s\n\n", subjectLine(doc),
		plural(doc.Summary.Violations, "policy violation", "policy violations"), modeDescription(doc.Policy.Mode))

	writeRules(&b, doc.Policy.Rules)
	writeSeverityCounts(&b, doc.Summary)
	writeViolations(&b, doc.Vulnerabilities)
	writeSecrets(&b, doc.Secrets)
	writeImageSecretNote(&b, doc)
	writeMalware(&b, doc.Malware, doc.IsDirectory())
	writeNotChecked(&b, coverageOf(doc))
	writeExceptions(&b, doc.Exceptions)

	exceptions := ""
	if label := exceptionsFileLabel(doc.Exceptions); label != "" {
		exceptions = " · exceptions: " + cell(label)
	}
	fmt.Fprintf(&b, "<sub>Report %s · %s %s · scanned %s with %s · policy: %s%s</sub>\n",
		doc.ReportID, digestLabel(doc), code(doc.Image.Digest), formatTime(doc.ScannedAt), scannerDescription(doc),
		doc.Policy.Source, exceptions)
	return b.String()
}

// subjectLine names what was scanned: the image reference, or the
// directory's name, version and scanned path.
func subjectLine(doc Document) string {
	if !doc.IsDirectory() {
		return code(doc.Image.Reference)
	}
	d := directoryOf(doc)
	line := "Directory " + code(d.Label())
	if d.Path != "" {
		line += " · " + code(d.Path)
	}
	return line
}

func digestLabel(doc Document) string {
	if doc.IsDirectory() {
		return "tree digest"
	}
	return "digest"
}

// code puts text in an inline code span that it cannot break out of.
func code(s string) string {
	return "`" + strings.ReplaceAll(cell(s), "`", "'") + "`"
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

// writeImageSecretNote says which files an image's secret scan skipped;
// directory scans list them instead (see writeNotChecked).
func writeImageSecretNote(b *strings.Builder, doc Document) {
	if note := imageSecretNote(doc); note != "" {
		fmt.Fprintf(b, "<sub>%s</sub>\n\n", note)
	}
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

func writeMalware(b *strings.Builder, m *MalwareSection, directory bool) {
	if m == nil {
		return
	}
	engines := make([]string, 0, len(m.Engines))
	for _, e := range m.Engines {
		engines = append(engines, engineLabel(e))
	}
	where := "in " + plural(m.Layers, "layer", "layers")
	if directory {
		where = "of the directory"
	}
	fmt.Fprintf(b, "### Malware\n\nScanned %s (%s) %s with %s. %s.\n\n", plural(m.FilesScanned, "file", "files"), formatBytes(m.BytesScanned),
		where, strings.Join(engines, " and "), plural(len(m.Findings), "detection", "detections"))
	if limits := malwareLimits(m); limits != "" {
		b.WriteString(limits + "\n\n")
	}
	writeMalwareFindings(b, m.Findings, directory)
	if len(m.Skipped) > 0 {
		fmt.Fprintf(b, "%s not fully scanned (size limit or a ClamAV limit); see results.json.\n\n",
			plural(len(m.Skipped), "file was", "files were"))
	}
}

// writeMalwareFindings lists detections; directories have no layer column.
func writeMalwareFindings(b *strings.Builder, findings []policy.MalwareFinding, directory bool) {
	if len(findings) == 0 {
		return
	}
	if directory {
		b.WriteString("| Engine | Signature | File | Status |\n|---|---|---|---|\n")
	} else {
		b.WriteString("| Engine | Signature | File | Layer | Status |\n|---|---|---|---:|---|\n")
	}
	for _, f := range findings {
		layer := ""
		if !directory {
			layer = fmt.Sprintf(" %d |", f.Layer)
		}
		fmt.Fprintf(b, "| %s | %s | %s |%s %s |\n", cell(f.Engine), cell(f.Signature), cell(f.Path), layer,
			findingStatus(f.ExceptionID, f.Violation))
	}
	b.WriteString("\n")
}

func engineLabel(e model.MalwareEngine) string {
	label := e.Name + " " + e.Version
	switch {
	case e.Database != "" && e.DatabaseDate != "":
		label += fmt.Sprintf(" (%s, %s)", e.Database, e.DatabaseDate)
	case e.Database != "":
		label += fmt.Sprintf(" (%s)", e.Database)
	}
	return label
}

// maxMarkdownPaths bounds the paths listed in the job summary.
const maxMarkdownPaths = 10

// writeNotChecked says which files of a directory Trivy did not read.
func writeNotChecked(b *strings.Builder, c *model.Coverage) {
	if c == nil {
		return
	}
	b.WriteString("### Not checked\n\n")
	if n := c.NotScanned.Files; n > 0 {
		paths := []string{}
		for i, p := range c.NotScanned.Paths {
			if i == maxMarkdownPaths {
				break
			}
			paths = append(paths, fmt.Sprintf("%s (%s, %s)", code(p.Path), plural(p.Files, "file", "files"), cell(p.Reason)))
		}
		fmt.Fprintf(b, "%s not checked for vulnerabilities or secrets: %s.\n\n",
			plural(n, "file was", "files were"), strings.Join(paths, ", "))
	}
	if n := c.SecretsNotChecked.Files; n > 0 {
		fmt.Fprintf(b, "%s not checked for secrets: %s. results.json lists them.\n\n",
			plural(n, "file was", "files were"), cell(byReason(c.SecretsNotChecked.ByReason)))
	}
	for _, caveat := range c.Caveats {
		fmt.Fprintf(b, "⚠️ %s\n\n", cell(caveat))
	}
}

func writeExceptions(b *strings.Builder, e Exceptions) {
	elsewhere := outOfScopeText(e.OutOfScope)
	if len(e.Applied)+len(e.Expired)+len(e.Unused) == 0 && elsewhere == "" {
		return
	}
	b.WriteString("### Exceptions\n\n")
	if elsewhere != "" {
		b.WriteString(cell(elsewhere) + "\n\n")
	}
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
	finding := cell(ex.Finding)
	if len(ex.Artifact) > 0 {
		names := make([]string, 0, len(ex.Artifact))
		for _, a := range ex.Artifact {
			names = append(names, code(a)) // a trailing * must not start emphasis
		}
		finding += ", only in " + strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s (%s, %s %s)", cell(ex.ID), finding, verb, ex.Expires)
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.Join(strings.Fields(s), " ")
}
