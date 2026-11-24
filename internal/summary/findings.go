package summary

import (
	"cmp"
	"slices"
	"time"

	"github.com/HowardLee12/scanproof/internal/policy"
)

// Status of a finding in findings.csv, judged at the summary's as-of time.
const (
	StatusOpenInSLA       = "open_in_sla"
	StatusOpenOverdue     = "open_overdue"
	StatusFixedInSLA      = "fixed_in_sla"
	StatusFixedLate       = "fixed_late"
	StatusAccepted        = ResolutionAccepted
	StatusNoLongerFixable = ResolutionNoFix
)

// FindingRow is one tracked finding in findings.csv. Times are RFC 3339 in
// UTC; the report fields hold ScanProof report IDs.
type FindingRow struct {
	Image           string   `json:"image"`
	ArtifactType    string   `json:"artifact_type"`
	ID              string   `json:"id"`
	Package         string   `json:"package"`
	Severity        string   `json:"severity"`
	FirstSeen       string   `json:"first_seen_utc"`
	Due             string   `json:"due_utc"`
	Status          string   `json:"status"`
	ClosedAt        string   `json:"closed_at_utc"`
	DaysOpen        float64  `json:"days_open"`
	SLADays         int      `json:"sla_days"`
	Reopened        int      `json:"reopened"`
	FirstSeenReport string   `json:"first_seen_report"`
	LastSeenReport  string   `json:"last_seen_report"`
	ClosedBy        []string `json:"closed_by_reports"`
}

// listFindings lists the tracked findings that matter to the period: first
// seen in it, closed in it, or still open at asOf. These are the findings
// counted in the remediation table. They are ordered by first-seen time,
// then image, ID and package.
func listFindings(tracked []TrackedFinding, pol policy.Policy, p Period, asOf time.Time) []FindingRow {
	relevant := make([]TrackedFinding, 0, len(tracked))
	for _, f := range tracked {
		if f.ClosedAt == nil || p.Contains(f.FirstSeen) || p.Contains(*f.ClosedAt) {
			relevant = append(relevant, f)
		}
	}
	slices.SortStableFunc(relevant, func(a, b TrackedFinding) int {
		return cmp.Or(a.FirstSeen.Compare(b.FirstSeen), cmp.Compare(a.Image, b.Image),
			cmp.Compare(a.ID, b.ID), cmp.Compare(a.Package, b.Package))
	})
	rows := make([]FindingRow, 0, len(relevant))
	for _, f := range relevant {
		rows = append(rows, findingRow(f, pol, asOf))
	}
	return rows
}

func findingRow(f TrackedFinding, pol policy.Policy, asOf time.Time) FindingRow {
	closedAt := ""
	if f.ClosedAt != nil {
		closedAt = rfc3339(*f.ClosedAt)
	}
	return FindingRow{
		Image: f.Image, ArtifactType: f.ArtifactType, ID: f.ID, Package: f.Package, Severity: f.Severity.String(),
		FirstSeen: rfc3339(f.FirstSeen), Due: rfc3339(f.Due), Status: findingStatus(f, asOf), ClosedAt: closedAt,
		DaysOpen: round1(f.DaysOpen(asOf)), SLADays: pol.SLA(f.Severity), Reopened: f.Reopened,
		FirstSeenReport: f.FirstSeenReport, LastSeenReport: f.LastSeenReport, ClosedBy: orEmpty(f.ClosedBy),
	}
}

// findingStatus uses the same rules as the remediation table.
func findingStatus(f TrackedFinding, asOf time.Time) string {
	switch {
	case f.ClosedAt == nil && asOf.After(f.Due):
		return StatusOpenOverdue
	case f.ClosedAt == nil:
		return StatusOpenInSLA
	case f.Fixed() && f.ClosedAt.After(f.Due):
		return StatusFixedLate
	case f.Fixed():
		return StatusFixedInSLA
	default:
		return f.Resolution
	}
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
