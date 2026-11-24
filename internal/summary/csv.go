package summary

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
)

var populationHeader = []string{
	"report_id", "scanned_at_utc", "trigger", "image", "digest", "verdict",
	"violations", "repository", "commit", "evidence", "artifact_type",
}

var findingsHeader = []string{
	"image", "artifact_type", "id", "package", "severity", "first_seen_utc", "due_utc", "status",
	"closed_at_utc", "days_open", "sla_days", "reopened", "first_seen_report", "last_seen_report",
	"closed_by_reports",
}

// reportSeparator joins several report IDs in one cell.
const reportSeparator = ";"

// PopulationCSV renders one row per scan for audit sampling.
func PopulationCSV(rows []PopulationRow) ([]byte, error) {
	records := make([][]string, 0, len(rows))
	for _, r := range rows {
		records = append(records, []string{
			r.ReportID, r.ScannedAt, r.Trigger, r.Image, r.Digest, r.Verdict,
			strconv.Itoa(r.Violations), r.Repository, r.Commit, r.Evidence, r.ArtifactType,
		})
	}
	return writeCSV("population", populationHeader, records)
}

// FindingsCSV renders one row per tracked finding, so an auditor can sample
// individual fixes and open the scans that show when each was first seen and
// when it went away.
func FindingsCSV(rows []FindingRow) ([]byte, error) {
	records := make([][]string, 0, len(rows))
	for _, r := range rows {
		records = append(records, []string{
			r.Image, r.ArtifactType, r.ID, r.Package, r.Severity, r.FirstSeen, r.Due, r.Status,
			r.ClosedAt, strconv.FormatFloat(r.DaysOpen, 'f', 1, 64), strconv.Itoa(r.SLADays),
			strconv.Itoa(r.Reopened), r.FirstSeenReport, r.LastSeenReport,
			strings.Join(r.ClosedBy, reportSeparator),
		})
	}
	return writeCSV("findings", findingsHeader, records)
}

// writeCSV renders the header and records. Every cell goes through
// neutralize here, so no CSV that ScanProof writes can carry a formula.
func writeCSV(name string, header []string, records [][]string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	for _, record := range append([][]string{header}, records...) {
		if err := w.Write(neutralizeAll(record)); err != nil {
			return nil, fmt.Errorf("write %s row: %w", name, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("write %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func neutralizeAll(record []string) []string {
	out := make([]string, len(record))
	for i, v := range record {
		out[i] = neutralize(v)
	}
	return out
}

// neutralize stops spreadsheet programs from treating a cell as a formula
// (CSV injection). As OWASP recommends, a cell that starts with =, +, -, @,
// tab or carriage return gets a leading single quote. encoding/csv quotes any
// cell that holds a comma, quote or line break, so a value cannot start a new
// cell either.
func neutralize(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
