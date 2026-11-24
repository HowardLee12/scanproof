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
	"violations", "repository", "commit", "evidence",
}

// PopulationCSV renders one row per scan for audit sampling.
func PopulationCSV(rows []PopulationRow) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(populationHeader); err != nil {
		return nil, fmt.Errorf("write population header: %w", err)
	}
	for _, r := range rows {
		record := []string{
			r.ReportID, r.ScannedAt, r.Trigger, r.Image, r.Digest, r.Verdict,
			strconv.Itoa(r.Violations), r.Repository, r.Commit, r.Evidence,
		}
		for i, v := range record {
			record[i] = neutralize(v)
		}
		if err := w.Write(record); err != nil {
			return nil, fmt.Errorf("write population row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("write population: %w", err)
	}
	return buf.Bytes(), nil
}

// neutralize stops spreadsheet programs from treating a cell as a formula.
func neutralize(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
