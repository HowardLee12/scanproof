package summary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

// SchemaVersion identifies the layout of summary.json.
const SchemaVersion = "scanproof-summary/v1"

// Input is everything Build needs.
type Input struct {
	ID            string
	GeneratedAt   time.Time
	Tool          report.Tool
	Period        Period
	Policy        policy.Policy
	StoreLocation string
	Scans         []Loaded
	// Incomplete lists scan folders skipped because their upload never
	// finished.
	Incomplete []string
}

// PeriodInfo describes the reporting window.
type PeriodInfo struct {
	From         string    `json:"from"`
	To           string    `json:"to"`
	Days         int       `json:"days"`
	LookbackDays int       `json:"lookback_days"`
	AsOf         time.Time `json:"as_of"`
}

// Coverage shows whether scanning ran throughout the period.
type Coverage struct {
	Scans            int `json:"scans"`
	CIScans          int `json:"ci_scans"`
	RescanScans      int `json:"rescan_scans"`
	ManualScans      int `json:"manual_scans"`
	Images           int `json:"images"`
	Repositories     int `json:"repositories"`
	Pass             int `json:"pass"`
	Warn             int `json:"warn"`
	Fail             int `json:"fail"`
	ScansWithSecrets int `json:"scans_with_secrets"`
	MalwareScans     int `json:"malware_scans"`
	MalwareFound     int `json:"malware_detections"`
	DaysInPeriod     int `json:"days_in_period"`
	DaysWithRescans  int `json:"days_with_rescans"`
}

// SeverityRemediation measures fixes against the SLA for one severity.
type SeverityRemediation struct {
	Severity        model.Severity `json:"severity"`
	SLADays         int            `json:"sla_days"`
	Opened          int            `json:"opened"`
	Fixed           int            `json:"fixed"`
	FixedInSLA      int            `json:"fixed_in_sla"`
	MedianDaysToFix float64        `json:"median_days_to_fix"`
	ClosedOther     int            `json:"closed_other"`
	OpenInSLA       int            `json:"open_in_sla"`
	OpenOverdue     int            `json:"open_overdue"`
}

// ExceptionActivity lists exception IDs seen in the period.
type ExceptionActivity struct {
	Applied []string `json:"applied"`
	Expired []string `json:"expired"`
}

// PopulationRow is one scan in the period.
type PopulationRow struct {
	ReportID   string `json:"report_id"`
	ScannedAt  string `json:"scanned_at_utc"`
	Trigger    string `json:"trigger"`
	Image      string `json:"image"`
	Digest     string `json:"digest"`
	Verdict    string `json:"verdict"`
	Violations int    `json:"violations"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Evidence   string `json:"evidence"`
}

// Summary is the content of summary.json.
type Summary struct {
	Schema          string                `json:"schema"`
	SummaryID       string                `json:"summary_id"`
	GeneratedAt     time.Time             `json:"generated_at"`
	Tool            report.Tool           `json:"tool"`
	Period          PeriodInfo            `json:"period"`
	Store           string                `json:"store"`
	Coverage        Coverage              `json:"coverage"`
	Remediation     []SeverityRemediation `json:"remediation"`
	FixedLate       []TrackedFinding      `json:"fixed_late"`
	Overdue         []TrackedFinding      `json:"overdue"`
	Exceptions      ExceptionActivity     `json:"exceptions"`
	Incomplete      []string              `json:"incomplete_uploads"`
	PopulationCount int                   `json:"population_count"`
	Population      []PopulationRow       `json:"-"`
	asOf            time.Time
}

// Build aggregates the loaded scans into a period summary.
func Build(in Input) Summary {
	inPeriod := make([]Loaded, 0, len(in.Scans))
	for _, s := range in.Scans {
		if in.Period.Contains(s.GeneratedAt) {
			inPeriod = append(inPeriod, s)
		}
	}
	asOf := in.Period.AsOf(in.GeneratedAt)
	tracked := track(in.Scans, in.Policy)
	remediation, late, overdue := remediate(tracked, in.Policy, in.Period, asOf)
	population := populationRows(inPeriod)

	return Summary{
		Schema:      SchemaVersion,
		SummaryID:   in.ID,
		GeneratedAt: in.GeneratedAt.UTC(),
		Tool:        in.Tool,
		Period: PeriodInfo{
			From: in.Period.From.Format("2006-01-02"), To: in.Period.To.Format("2006-01-02"),
			Days: in.Period.Days(), LookbackDays: in.Period.LookbackDays, AsOf: asOf,
		},
		Store:           in.StoreLocation,
		Coverage:        coverage(inPeriod, in.Period.DaysUntil(asOf)),
		Remediation:     remediation,
		FixedLate:       late,
		Overdue:         overdue,
		Exceptions:      exceptionActivity(inPeriod),
		Incomplete:      orEmpty(in.Incomplete),
		PopulationCount: len(population),
		Population:      population,
		asOf:            asOf,
	}
}

func coverage(scans []Loaded, daysSoFar int) Coverage {
	c := Coverage{Scans: len(scans), DaysInPeriod: daysSoFar}
	digests, repos, rescanDays := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range scans {
		switch s.Trigger {
		case report.TriggerCI:
			c.CIScans++
		case report.TriggerRescan:
			c.RescanScans++
			rescanDays[s.GeneratedAt.Format("2006-01-02")] = true
		default:
			c.ManualScans++
		}
		switch s.Verdict {
		case policy.VerdictPass:
			c.Pass++
		case policy.VerdictWarn:
			c.Warn++
		case policy.VerdictFail:
			c.Fail++
		}
		if len(s.Secrets) > 0 {
			c.ScansWithSecrets++
		}
		if s.Malware != nil {
			c.MalwareScans++
			c.MalwareFound += len(s.Malware.Findings)
		}
		key := s.Image.Digest
		if key == "" {
			key = s.Image.Reference
		}
		digests[key] = true
		repos[imageName(s.Image.Reference)] = true
	}
	c.Images, c.Repositories, c.DaysWithRescans = len(digests), len(repos), len(rescanDays)
	return c
}

func remediate(tracked []TrackedFinding, pol policy.Policy, p Period, asOf time.Time) ([]SeverityRemediation, []TrackedFinding, []TrackedFinding) {
	rows := []SeverityRemediation{}
	late, overdue := []TrackedFinding{}, []TrackedFinding{}
	for _, sev := range model.AllSeverities() {
		sla := pol.SLA(sev)
		if sla == 0 {
			continue
		}
		row := SeverityRemediation{Severity: sev, SLADays: sla}
		fixDays := []float64{}
		for _, f := range tracked {
			if f.Severity != sev {
				continue
			}
			if p.Contains(f.FirstSeen) {
				row.Opened++
			}
			switch {
			case f.ClosedAt != nil && p.Contains(*f.ClosedAt) && f.Fixed():
				row.Fixed++
				fixDays = append(fixDays, f.DaysOpen(asOf))
				if !f.ClosedAt.After(f.Due) {
					row.FixedInSLA++
				} else {
					late = append(late, f)
				}
			case f.ClosedAt != nil && p.Contains(*f.ClosedAt):
				row.ClosedOther++
			case f.ClosedAt == nil && asOf.After(f.Due):
				row.OpenOverdue++
				overdue = append(overdue, f)
			case f.ClosedAt == nil:
				row.OpenInSLA++
			}
		}
		row.MedianDaysToFix = median(fixDays)
		rows = append(rows, row)
	}
	return rows, late, overdue
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64{}, values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return round1(sorted[mid])
	}
	return round1((sorted[mid-1] + sorted[mid]) / 2)
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func exceptionActivity(scans []Loaded) ExceptionActivity {
	applied, expired := map[string]bool{}, map[string]bool{}
	for _, s := range scans {
		for _, ex := range s.Exceptions.Applied {
			applied[ex.ID] = true
		}
		for _, ex := range s.Exceptions.Expired {
			expired[ex.ID] = true
		}
	}
	return ExceptionActivity{Applied: sortedKeys(applied), Expired: sortedKeys(expired)}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func populationRows(scans []Loaded) []PopulationRow {
	rows := make([]PopulationRow, 0, len(scans))
	for _, s := range scans {
		rows = append(rows, PopulationRow{
			ReportID:   s.ReportID,
			ScannedAt:  s.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
			Trigger:    s.Trigger,
			Image:      s.Image.Reference,
			Digest:     s.Image.Digest,
			Verdict:    string(s.Verdict),
			Violations: s.Summary.Violations,
			Repository: s.Context.Repository,
			Commit:     s.Context.Commit,
			Evidence:   s.Location,
		})
	}
	return rows
}

// remediation returns the row for one severity, or an empty row.
func (s Summary) remediation(sev model.Severity) SeverityRemediation {
	for _, r := range s.Remediation {
		if r.Severity == sev {
			return r
		}
	}
	return SeverityRemediation{Severity: sev}
}

// NewSummaryID returns an ID such as PS-20261001-7F3A9C.
func NewSummaryID(now time.Time) (string, error) {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate summary ID: %w", err)
	}
	return fmt.Sprintf("PS-%s-%s", now.UTC().Format("20060102"), strings.ToUpper(hex.EncodeToString(buf))), nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
