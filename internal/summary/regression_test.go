package summary

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

// regressionGenerated is when the regression summary is made: just after the
// period, so open findings are judged at the end of the period.
var regressionGenerated = time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)

// regressionScans adds every tracking rule to sampleScans:
//   - repo/union: prod (union:1) keeps a Critical while staging (union:2)
//     is clean, every day for five days; on day 6 two clean scans close it
//   - repo/reopen: a High fixed on day 4, back on day 30, fixed late on day 50
//   - repo/accept: a Critical accepted by an exception, and a High whose fix
//     disappears, both on day 9
//   - dir:model-env: a Medium in a directory, still open at the end
//   - repo/old: a Critical opened and fixed inside the look-back window
//   - repo/legacy: a Medium first seen in the look-back window, still open
//   - repo/late: a High first seen on day 85, open but inside its SLA
func regressionScans() []Loaded {
	scans := append([]Loaded{}, sampleScans()...)
	scans = append(scans, unionScans()...)
	scans = append(scans, reopenScans()...)
	scans = append(scans, acceptScans()...)
	scans = append(scans, otherScans()...)
	return sortedByTime(scans)
}

func unionScans() []Loaded {
	crit := finding("CVE-U1", "openssl", model.SeverityCritical, "3.0.15")
	scans := []Loaded{}
	for n := 1; n <= 5; n++ {
		scans = append(scans, loaded(
			scanDoc(fmt.Sprintf("SR-UP%d", n), "repo/union:1", "sha256:u1", day(n), report.TriggerRescan, policy.VerdictWarn, crit),
			scanDoc(fmt.Sprintf("SR-US%d", n), "repo/union:2", "sha256:u2", day(n).Add(time.Minute), report.TriggerRescan, policy.VerdictPass),
		)...)
	}
	return append(scans, loaded(
		scanDoc("SR-UP6", "repo/union:2", "sha256:u2", day(6), report.TriggerRescan, policy.VerdictPass),
		scanDoc("SR-US6", "repo/union:2", "sha256:u2", day(6).Add(2*time.Hour), report.TriggerRescan, policy.VerdictPass),
	)...)
}

func reopenScans() []Loaded {
	high := finding("CVE-R1", "curl", model.SeverityHigh, "8.9.1")
	return loaded(
		scanDoc("SR-R1", "repo/reopen:1", "sha256:r1", day(3), report.TriggerCI, policy.VerdictWarn, high),
		scanDoc("SR-R2", "repo/reopen:2", "sha256:r2", day(4), report.TriggerCI, policy.VerdictPass),
		scanDoc("SR-R3", "repo/reopen:1", "sha256:r1", day(30), report.TriggerRescan, policy.VerdictWarn, high),
		scanDoc("SR-R4", "repo/reopen:1", "sha256:r1", day(31), report.TriggerRescan, policy.VerdictWarn, high),
		scanDoc("SR-R5", "repo/reopen:3", "sha256:r3", day(50), report.TriggerCI, policy.VerdictPass),
	)
}

func acceptScans() []Loaded {
	crit := finding("CVE-AC", "busybox", model.SeverityCritical, "1.36.1")
	accepted := crit
	accepted.ExceptionID = "EX-7"
	high := finding("CVE-NF", "zlib", model.SeverityHigh, "1.3.1")
	noFix := finding("CVE-NF", "zlib", model.SeverityHigh, "")
	return loaded(
		scanDoc("SR-AC1", "repo/accept:1", "sha256:ac1", day(7), report.TriggerCI, policy.VerdictWarn, crit, high),
		scanDoc("SR-AC2", "repo/accept:1", "sha256:ac1", day(9), report.TriggerRescan, policy.VerdictPass, accepted, noFix),
	)
}

func otherScans() []Loaded {
	medium := finding("CVE-DV", "urllib3", model.SeverityMedium, "1.26.5")
	oldCrit := finding("CVE-O1", "openssl", model.SeverityCritical, "3.0.15")
	legacy := finding("CVE-LG", "expat", model.SeverityMedium, "2.6.3")
	late := finding("CVE-LT", "nghttp2", model.SeverityHigh, "1.64.0")
	return append(
		loaded(
			dirDoc("SR-D1", "dir:model-env:1.0", "sha256:t1", 2, report.TriggerCI, medium),
			dirDoc("SR-D2", "dir:model-env:1.0", "sha256:t1", 80, report.TriggerRescan, medium),
			scanDoc("SR-L1", "repo/late:1", "sha256:l1", day(85), report.TriggerCI, policy.VerdictWarn, late),
		),
		loaded(
			scanDoc("SR-O1", "repo/old:1", "sha256:o1", periodFrom.AddDate(0, 0, -50), report.TriggerCI, policy.VerdictWarn, oldCrit),
			scanDoc("SR-O2", "repo/old:2", "sha256:o2", periodFrom.AddDate(0, 0, -40), report.TriggerCI, policy.VerdictPass),
			scanDoc("SR-LG1", "repo/legacy:1", "sha256:lg1", periodFrom.AddDate(0, 0, -60), report.TriggerCI, policy.VerdictWarn, legacy),
			scanDoc("SR-LG2", "repo/legacy:1", "sha256:lg1", day(60), report.TriggerRescan, policy.VerdictWarn, legacy),
		)...,
	)
}

// sortedByTime orders scans as Load does: oldest first, then by report ID.
func sortedByTime(scans []Loaded) []Loaded {
	out := append([]Loaded{}, scans...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].GeneratedAt.Equal(out[j].GeneratedAt) {
			return out[i].GeneratedAt.Before(out[j].GeneratedAt)
		}
		return out[i].ReportID < out[j].ReportID
	})
	return out
}

func regressionSummary() Summary {
	return Build(Input{
		ID: "PS-20261001-REGRES", GeneratedAt: regressionGenerated,
		Tool: report.Tool{Name: "scanproof", Version: "test"}, Period: testPeriod(),
		Policy: policy.Default(), StoreLocation: "file:///evidence/", Scans: regressionScans(),
	})
}

// TestRemediationIsUnchanged pins the remediation table, the fixed-late list
// and the overdue list to what they were before findings.csv existed. The
// golden file was produced by the earlier code and must not be regenerated
// to make this test pass.
func TestRemediationIsUnchanged(t *testing.T) {
	s := regressionSummary()
	got, err := json.MarshalIndent(struct {
		Remediation []SeverityRemediation `json:"remediation"`
		FixedLate   []TrackedFinding      `json:"fixed_late"`
		Overdue     []TrackedFinding      `json:"overdue"`
	}{s.Remediation, s.FixedLate, s.Overdue}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "remediation_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("remediation changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
