package summary

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/report"
)

//go:embed templates/summary.typ
var summaryTemplate []byte

// maxPopulationRows bounds the population table in the PDF; population.csv
// has every scan.
const maxPopulationRows = 40

type row struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Mono  bool   `json:"mono"`
}

type tile struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Hint   string `json:"hint"`
	Accent string `json:"accent"`
}

type pdfView struct {
	SummaryID         string     `json:"summary_id"`
	AsOf              string     `json:"as_of"`
	GeneratedAt       string     `json:"generated_at"`
	ToolVersion       string     `json:"tool_version"`
	PeriodLabel       string     `json:"period_label"`
	Tiles             []tile     `json:"tiles"`
	Remediation       [][]string `json:"remediation"`
	FindingsCount     int        `json:"findings_count"`
	FixedLate         [][]string `json:"fixed_late"`
	Overdue           [][]string `json:"overdue"`
	ExceptionsApplied string     `json:"exceptions_applied"`
	ExceptionsExpired string     `json:"exceptions_expired"`
	Population        [][]string `json:"population"`
	PopulationOmitted int        `json:"population_omitted"`
	Evidence          []row      `json:"evidence"`
}

// RenderPDF writes summary.pdf. hashes maps output file names to their
// SHA-256, printed so readers can check the CSV and JSON files.
func RenderPDF(ctx context.Context, r report.PDFRenderer, s Summary, hashes map[string]string, outPath string) error {
	return r.RenderTemplate(ctx, summaryTemplate, newPDFView(s, hashes), s.GeneratedAt, outPath)
}

func newPDFView(s Summary, hashes map[string]string) pdfView {
	c := s.Coverage
	overdueAccent := "#137a3f"
	if len(s.Overdue) > 0 {
		overdueAccent = "#b42318"
	}
	population, omitted := populationView(s.Population)
	return pdfView{
		SummaryID:   s.SummaryID,
		AsOf:        s.asOf.UTC().Format("2006-01-02 15:04 UTC"),
		GeneratedAt: s.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		ToolVersion: s.Tool.Version,
		PeriodLabel: fmt.Sprintf("%s to %s · %s", s.Period.From, s.Period.To, plural(s.Period.Days, "day", "days")),
		Tiles: []tile{
			{"Scans", strconv.Itoa(c.Scans), fmt.Sprintf("%d CI · %d rescans · %d manual", c.CIScans, c.RescanScans, c.ManualScans), "#123a5a"},
			{"Images", strconv.Itoa(c.Images), fmt.Sprintf("in %d repositories", c.Repositories) + strings.Replace(directoriesPhrase(c), " and ", " · ", 1), "#123a5a"},
			{"Passed", strconv.Itoa(c.Pass), fmt.Sprintf("%d warned · %d failed", c.Warn, c.Fail), "#137a3f"},
			{"Days rescanned", fmt.Sprintf("%d / %d", c.DaysWithRescans, c.DaysInPeriod), "days with a rescan", "#123a5a"},
			{"Scans with secrets", strconv.Itoa(c.ScansWithSecrets), "keys, tokens, passwords", "#6b7785"},
			{"Malware checks", strconv.Itoa(c.MalwareScans), "scans that checked every file", "#123a5a"},
			{"Malware detections", strconv.Itoa(c.MalwareFound), "across those scans", malwareAccent(c.MalwareFound)},
			{"Open past SLA", strconv.Itoa(len(s.Overdue)), "at the end of the period", overdueAccent},
		},
		Remediation:       remediationRows(s.Remediation),
		FindingsCount:     s.FindingsCount,
		FixedLate:         findingRows(s.FixedLate, s.asOf, true),
		Overdue:           findingRows(s.Overdue, s.asOf, false),
		ExceptionsApplied: listOrNone(s.Exceptions.Applied),
		ExceptionsExpired: listOrNone(s.Exceptions.Expired),
		Population:        population,
		PopulationOmitted: omitted,
		Evidence:          evidenceRows(s, hashes),
	}
}

func remediationRows(in []SeverityRemediation) [][]string {
	rows := make([][]string, 0, len(in))
	for _, r := range in {
		inSLA := "—"
		if r.Fixed > 0 {
			inSLA = fmt.Sprintf("%d (%d%%)", r.FixedInSLA, r.FixedInSLA*100/r.Fixed)
		}
		rows = append(rows, []string{
			r.Severity.String(), strconv.Itoa(r.SLADays), strconv.Itoa(r.Opened), strconv.Itoa(r.Fixed),
			inSLA, formatDays(r.MedianDaysToFix), strconv.Itoa(r.ClosedOther), strconv.Itoa(r.OpenInSLA), strconv.Itoa(r.OpenOverdue),
		})
	}
	return rows
}

func findingRows(findings []TrackedFinding, end time.Time, fixed bool) [][]string {
	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		last := f.LastSeen.Format("2006-01-02")
		if fixed && f.ClosedAt != nil {
			last = f.ClosedAt.Format("2006-01-02")
		}
		rows = append(rows, []string{
			f.Image, f.ID, f.Package, f.Severity.String(), f.FirstSeen.Format("2006-01-02"),
			f.Due.Format("2006-01-02"), last, strconv.FormatFloat(round1(f.DaysOpen(end)), 'f', -1, 64),
		})
	}
	return rows
}

func populationView(all []PopulationRow) ([][]string, int) {
	rows := make([][]string, 0, maxPopulationRows)
	for i, p := range all {
		if i == maxPopulationRows {
			break
		}
		rows = append(rows, []string{p.ReportID, p.ScannedAt, p.Trigger, p.Image, p.Verdict})
	}
	return rows, len(all) - len(rows)
}

func evidenceRows(s Summary, hashes map[string]string) []row {
	rows := []row{{Label: "Summary ID", Value: s.SummaryID}, {Label: "Source", Value: s.Store}}
	for _, name := range []string{"population.csv", "findings.csv", "summary.json"} {
		if h := hashes[name]; h != "" {
			rows = append(rows, row{Label: name + " SHA-256", Value: h, Mono: true})
		}
	}
	rows = append(rows, row{Label: "Look-back", Value: fmt.Sprintf("%d days before the period, to date findings that were already open", s.Period.LookbackDays)})
	if len(s.Incomplete) > 0 {
		rows = append(rows, row{Label: "Incomplete uploads", Value: fmt.Sprintf("%d scan folders without a manifest were left out: %s", len(s.Incomplete), strings.Join(s.Incomplete, ", "))})
	}
	return rows
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func malwareAccent(found int) string {
	if found > 0 {
		return "#b42318"
	}
	return "#137a3f"
}
