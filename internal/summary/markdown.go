package summary

import (
	"fmt"
	"strconv"
	"strings"
)

// maxMarkdownFindings keeps the job summary short; summary.json has all.
const maxMarkdownFindings = 20

// Markdown renders a short version of the summary for CI job pages.
func Markdown(s Summary) string {
	var b strings.Builder
	c := s.Coverage
	fmt.Fprintf(&b, "## ScanProof period summary: %s to %s\n\n", s.Period.From, s.Period.To)
	fmt.Fprintf(&b, "%d scans (%d CI, %d rescans, %d manual) of %d images in %d repositories%s. "+
		"Rescans ran on %d of %d days. Verdicts: %d pass, %d warn, %d fail. "+
		"Malware checks: %d scans, %d detections.\n\n",
		c.Scans, c.CIScans, c.RescanScans, c.ManualScans, c.Images, c.Repositories, directoriesPhrase(c),
		c.DaysWithRescans, c.DaysInPeriod, c.Pass, c.Warn, c.Fail, c.MalwareScans, c.MalwareFound)

	b.WriteString("| Severity | SLA days | Opened | Fixed | Fixed in SLA | Median days to fix | Accepted or no fix | Open in SLA | Open overdue |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range s.Remediation {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %s | %d | %d | %d |\n", r.Severity, r.SLADays, r.Opened, r.Fixed,
			r.FixedInSLA, formatDays(r.MedianDaysToFix), r.ClosedOther, r.OpenInSLA, r.OpenOverdue)
	}
	fmt.Fprintf(&b, "\nEvery tracked finding (%d) is listed in findings.csv, with its dates, its status and the "+
		"scan reports that show when it was first seen and when it went away.\n\n", s.FindingsCount)

	writeFindings(&b, "Fixed after the SLA", s.FixedLate)
	writeFindings(&b, "Open past the SLA at the end of the period", s.Overdue)

	if len(s.Exceptions.Applied)+len(s.Exceptions.Expired) > 0 {
		fmt.Fprintf(&b, "Exceptions applied: %s. Expired: %s.\n\n", listOrNone(s.Exceptions.Applied), listOrNone(s.Exceptions.Expired))
	}
	fmt.Fprintf(&b, "<sub>Summary %s · %d scans listed in population.csv · %d findings in findings.csv · source %s</sub>\n",
		s.SummaryID, s.PopulationCount, s.FindingsCount, s.Store)
	return b.String()
}

func writeFindings(b *strings.Builder, title string, findings []TrackedFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n\n| Image | ID | Package | Severity | First seen | Due |\n|---|---|---|---|---|---|\n", title)
	for i, f := range findings {
		if i == maxMarkdownFindings {
			fmt.Fprintf(b, "\n_…and %d more in summary.json_\n", len(findings)-maxMarkdownFindings)
			break
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n", cell(f.Image), cell(f.ID), cell(f.Package),
			f.Severity, f.FirstSeen.Format("2006-01-02"), f.Due.Format("2006-01-02"))
	}
	b.WriteString("\n")
}

// directoriesPhrase is " and N directories" when directories were scanned.
func directoriesPhrase(c Coverage) string {
	if c.Directories == 0 {
		return ""
	}
	return " and " + plural(c.Directories, "directory", "directories")
}

func formatDays(d float64) string {
	return strconv.FormatFloat(d, 'f', -1, 64)
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func cell(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "|", `\|`)), " ")
}
