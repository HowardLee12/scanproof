package report

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
)

// maxPDFRows bounds the detailed vulnerability table; results.json has all.
const maxPDFRows = 80

// maxPackageRows bounds the Medium/Low summary table.
const maxPackageRows = 15

// pdfView is the data the Typst template renders. Every value is already
// formatted, so the template only handles layout.
type pdfView struct {
	Title              string     `json:"title"`
	Subtitle           string     `json:"subtitle"`
	ArtifactTitle      string     `json:"artifact_title"`
	Subject            string     `json:"subject"`
	ReportID           string     `json:"report_id"`
	GeneratedAt        string     `json:"generated_at"`
	ToolVersion        string     `json:"tool_version"`
	Verdict            string     `json:"verdict"`
	Headline           string     `json:"headline"`
	Detail             string     `json:"detail"`
	DigestShort        string     `json:"digest_short"`
	ArtifactRows       []pdfRow   `json:"artifact_rows"`
	ContextTitle       string     `json:"context_title"`
	ContextRows        []pdfRow   `json:"context_rows"`
	Tiles              []pdfTile  `json:"tiles"`
	Rules              []pdfRule  `json:"rules"`
	Scanners           [][]string `json:"scanners"`
	Vulns              []pdfVuln  `json:"vulns"`
	VulnsOmitted       int        `json:"vulns_omitted"`
	LowerByPackage     [][]string `json:"lower_by_package"`
	Secrets            [][]string `json:"secrets"`
	ExceptionsApplied  [][]string `json:"exceptions_applied"`
	ExceptionsExpired  [][]string `json:"exceptions_expired"`
	ExceptionsUnused   [][]string `json:"exceptions_unused"`
	IntegrityRows      []pdfRow   `json:"integrity_rows"`
	SecretsNote        string     `json:"secrets_note"`
	SecretsNone        string     `json:"secrets_none"`
	NotScanned         [][]string `json:"not_scanned"`
	SecretsSkipped     [][]string `json:"secrets_skipped"`
	SecretsSkippedNote string     `json:"secrets_skipped_note"`
	Malware            bool       `json:"malware"`
	LayerColumn        bool       `json:"layer_column"`
	MalwareEngines     [][]string `json:"malware_engines"`
	MalwareStats       string     `json:"malware_stats"`
	MalwareFindings    [][]string `json:"malware_findings"`
	MalwareSkipped     [][]string `json:"malware_skipped"`
	CC68Text           string     `json:"cc68_text"`
}

type pdfRow struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Mono  bool   `json:"mono"`
}

type pdfTile struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Hint   string `json:"hint"`
	Accent string `json:"accent"`
}

type pdfRule struct {
	Name      string `json:"name"`
	Threshold string `json:"threshold"`
	Found     string `json:"found"`
	Passed    bool   `json:"passed"`
}

type pdfVuln struct {
	Severity   string `json:"severity"`
	ID         string `json:"id"`
	Package    string `json:"package"`
	Installed  string `json:"installed"`
	Fixed      string `json:"fixed"`
	CVSS       string `json:"cvss"`
	Status     string `json:"status"`
	StatusKind string `json:"status_kind"`
}

var severityAccents = map[model.Severity]string{
	model.SeverityCritical: "#8f1d14",
	model.SeverityHigh:     "#d0451b",
	model.SeverityMedium:   "#c98a07",
	model.SeverityLow:      "#6b7785",
}

var verdictAccents = map[policy.Verdict]string{
	policy.VerdictPass: "#137a3f",
	policy.VerdictWarn: "#c98a07",
	policy.VerdictFail: "#b42318",
}

func newPDFView(doc Document, resultsSHA256 string) pdfView {
	vulns, omitted := criticalAndHigh(doc.Vulnerabilities)
	directory := doc.IsDirectory()
	return pdfView{
		Title:              pick(directory, "Directory Scan Report", "Container Image Scan Report"),
		Subtitle:           subtitle(doc),
		ArtifactTitle:      pick(directory, "Directory", "Image"),
		Subject:            subject(doc),
		ReportID:           doc.ReportID,
		GeneratedAt:        formatTime(doc.GeneratedAt),
		ToolVersion:        doc.Tool.Version,
		Verdict:            string(doc.Verdict),
		Headline:           headline(doc),
		Detail:             detail(doc),
		DigestShort:        shortDigest(doc.Image.Digest),
		ArtifactRows:       artifactRows(doc),
		ContextTitle:       contextTitle(doc),
		ContextRows:        contextRows(doc),
		Tiles:              tiles(doc),
		Rules:              rules(doc.Policy.Rules),
		Scanners:           [][]string{{titleCase(doc.Scanner.Name), doc.Scanner.Version, orText(formatTimePtr(doc.Scanner.DBUpdatedAt), "Not recorded")}},
		Vulns:              vulns,
		VulnsOmitted:       omitted,
		LowerByPackage:     lowerByPackage(doc.Vulnerabilities),
		Secrets:            secretRows(doc.Secrets),
		ExceptionsApplied:  exceptionRows(doc.Exceptions.Applied),
		ExceptionsExpired:  exceptionRows(doc.Exceptions.Expired),
		ExceptionsUnused:   exceptionRows(doc.Exceptions.Unused),
		IntegrityRows:      integrityRows(doc, resultsSHA256),
		SecretsNote:        secretsNote(doc),
		SecretsNone:        secretsNone(doc),
		NotScanned:         notScannedRows(coverageOf(doc)),
		SecretsSkipped:     secretsSkippedRows(coverageOf(doc)),
		SecretsSkippedNote: secretsSkippedNote(coverageOf(doc)),
		Malware:            doc.Malware != nil,
		LayerColumn:        !directory,
		MalwareEngines:     malwareEngines(doc.Malware),
		MalwareStats:       malwareStats(doc.Malware, directory),
		MalwareFindings:    malwareFindings(doc.Malware, directory),
		MalwareSkipped:     malwareSkipped(doc.Malware, directory),
		CC68Text:           cc68Text(doc.Malware, directory),
	}
}

func headline(doc Document) string {
	violations := plural(doc.Summary.Violations, "policy violation", "policy violations")
	switch doc.Verdict {
	case policy.VerdictPass:
		return fmt.Sprintf("All %s passed.", plural(len(doc.Policy.Rules), "policy rule", "policy rules"))
	case policy.VerdictFail:
		return violations + ". Enforce mode stops the pipeline."
	default:
		return violations + ". Reported only; the pipeline continues (warn mode)."
	}
}

func detail(doc Document) string {
	return fmt.Sprintf("Policy: %s (%s mode) · %s applied · scanned with %s %s",
		doc.Policy.Source, doc.Policy.Mode,
		plural(len(doc.Exceptions.Applied), "approved exception", "approved exceptions"),
		titleCase(doc.Scanner.Name), doc.Scanner.Version)
}

func nonEmpty(rows []pdfRow) []pdfRow {
	out := make([]pdfRow, 0, len(rows))
	for _, r := range rows {
		if r.Value != "" {
			out = append(out, r)
		}
	}
	return out
}

func tiles(doc Document) []pdfTile {
	out := make([]pdfTile, 0, 6)
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		c := doc.Summary.Count(sev)
		hint := fmt.Sprintf("%d fixable", c.Fixable)
		if c.Accepted > 0 {
			hint += fmt.Sprintf(" · %d accepted", c.Accepted)
		}
		out = append(out, pdfTile{Label: titleCase(lower(sev.String())), Value: strconv.Itoa(c.Total), Hint: hint, Accent: severityAccents[sev]})
	}
	secretHint := "keys, tokens, passwords"
	if doc.Summary.SecretsAccepted > 0 {
		secretHint = fmt.Sprintf("%d accepted", doc.Summary.SecretsAccepted)
	}
	out = append(out, pdfTile{Label: "Secrets", Value: strconv.Itoa(doc.Summary.Secrets), Hint: secretHint, Accent: "#6b7785"})
	if doc.Malware != nil {
		accent := "#137a3f"
		if doc.Summary.MalwareDetections > 0 {
			accent = "#b42318"
		}
		out = append(out, pdfTile{Label: "Malware", Value: strconv.Itoa(doc.Summary.MalwareDetections),
			Hint: fmt.Sprintf("%d files", doc.Malware.FilesScanned), Accent: accent})
	}
	out = append(out,
		pdfTile{Label: "Violations", Value: strconv.Itoa(doc.Summary.Violations), Hint: string(doc.Policy.Mode) + " mode", Accent: verdictAccents[doc.Verdict]},
	)
	return out
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func rules(in []policy.RuleResult) []pdfRule {
	out := make([]pdfRule, 0, len(in))
	for _, r := range in {
		out = append(out, pdfRule{Name: r.Name, Threshold: r.Threshold, Found: strconv.Itoa(r.Found), Passed: r.Passed})
	}
	return out
}

func criticalAndHigh(findings []policy.VulnerabilityFinding) ([]pdfVuln, int) {
	out := make([]pdfVuln, 0)
	total := 0
	for _, f := range findings {
		if f.Severity < model.SeverityHigh {
			continue
		}
		total++
		if len(out) == maxPDFRows {
			continue
		}
		status, kind := vulnStatus(f)
		cvss := ""
		if f.CVSS > 0 {
			cvss = strconv.FormatFloat(f.CVSS, 'f', 1, 64)
		}
		fixed := f.FixedVersion
		if fixed == "" {
			fixed = "No fix available"
		}
		out = append(out, pdfVuln{
			Severity: f.Severity.String(), ID: f.ID, Package: f.Package, Installed: f.InstalledVersion,
			Fixed: fixed, CVSS: cvss, Status: status, StatusKind: kind,
		})
	}
	return out, total - len(out)
}

func vulnStatus(f policy.VulnerabilityFinding) (string, string) {
	switch {
	case f.Accepted():
		return "Accepted · " + f.ExceptionID, "accepted"
	case f.Violation:
		return "Violation", "violation"
	case f.Fixable():
		return "Fix available", "fixable"
	default:
		return "No fix available", "nofix"
	}
}

func lowerByPackage(findings []policy.VulnerabilityFinding) [][]string {
	type counts struct{ medium, low, fixable int }
	byPkg := map[string]counts{}
	for _, f := range findings {
		if f.Severity != model.SeverityMedium && f.Severity != model.SeverityLow {
			continue
		}
		c := byPkg[f.Package]
		if f.Severity == model.SeverityMedium {
			c.medium++
		} else {
			c.low++
		}
		if f.Fixable() {
			c.fixable++
		}
		byPkg[f.Package] = c
	}
	names := make([]string, 0, len(byPkg))
	for name := range byPkg {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := byPkg[names[i]], byPkg[names[j]]
		if a.medium+a.low != b.medium+b.low {
			return a.medium+a.low > b.medium+b.low
		}
		return names[i] < names[j]
	})
	rows := make([][]string, 0, maxPackageRows)
	for i, name := range names {
		if i == maxPackageRows {
			rows = append(rows, []string{fmt.Sprintf("%d more packages in results.json", len(names)-maxPackageRows), "", "", ""})
			break
		}
		c := byPkg[name]
		rows = append(rows, []string{name, strconv.Itoa(c.medium), strconv.Itoa(c.low), strconv.Itoa(c.fixable)})
	}
	return rows
}

func secretRows(secrets []policy.SecretFinding) [][]string {
	rows := make([][]string, 0, len(secrets))
	for _, s := range secrets {
		rows = append(rows, []string{s.RuleID, s.Title, fmt.Sprintf("%s:%d", s.Target, s.Line), findingStatus(s.ExceptionID, s.Violation)})
	}
	return rows
}

func exceptionRows(list []exception.Exception) [][]string {
	rows := make([][]string, 0, len(list))
	for _, ex := range list {
		finding := ex.Finding
		if ex.Package != "" {
			finding += " in " + ex.Package
		}
		approver := ex.ApprovedBy
		if approver == "" {
			approver = "See the pull request that added it"
		}
		rows = append(rows, []string{ex.ID, finding, ex.Reason, approver, ex.Expires.String()})
	}
	return rows
}

func integrityRows(doc Document, resultsSHA256 string) []pdfRow {
	return nonEmpty([]pdfRow{
		{Label: "Report ID", Value: doc.ReportID},
		{Label: "results.json SHA-256", Value: resultsSHA256, Mono: true},
		{Label: "Policy", Value: doc.Policy.Source},
		{Label: "Policy SHA-256", Value: doc.Policy.SHA256, Mono: true},
		{Label: "Other files", Value: "Hashes of every output file are in manifest.json."},
	})
}

func orText(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
