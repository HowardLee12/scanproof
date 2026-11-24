package summary

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
)

func testPeriod() Period {
	return NewPeriod(periodFrom, periodTo, 90)
}

func TestPeriodBounds(t *testing.T) {
	p := testPeriod()
	if !p.Contains(time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC)) {
		t.Error("the last day is included")
	}
	if p.Contains(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("the day after is excluded")
	}
	if p.Days() != 92 || !p.LoadFrom().Equal(periodFrom.AddDate(0, 0, -90)) {
		t.Errorf("days %d, load from %v", p.Days(), p.LoadFrom())
	}
}

func TestImageName(t *testing.T) {
	cases := map[string]string{
		"repo/api:1":                                 "repo/api",
		"registry:5000/team/api:2.0":                 "registry:5000/team/api",
		"ghcr.io/org/app@sha256:abc":                 "ghcr.io/org/app",
		"ghcr.io/org/app:1.0@sha256:abc":             "ghcr.io/org/app",
		"alpine":                                     "alpine",
		"123.dkr.ecr.us-east-2.amazonaws.com/api:v1": "123.dkr.ecr.us-east-2.amazonaws.com/api",
	}
	for in, want := range cases {
		if got := imageName(in); got != want {
			t.Errorf("imageName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrackRemediation(t *testing.T) {
	tracked := track(sampleScans(), policy.Default())
	byID := map[string]TrackedFinding{}
	for _, f := range tracked {
		byID[f.ID] = f
	}
	if len(tracked) != 4 {
		t.Fatalf("got %d tracked findings, want CVE-A, B, C and D only: %+v", len(tracked), tracked)
	}
	a := byID["CVE-A"]
	if a.FixedAt == nil || !a.FixedAt.Equal(day(5)) || !a.FirstSeen.Equal(day(1)) || !a.Due.Equal(day(1).AddDate(0, 0, 15)) {
		t.Errorf("CVE-A = %+v", a)
	}
	b := byID["CVE-B"]
	if b.FixedAt == nil || !b.FixedAt.Equal(day(40)) {
		t.Errorf("CVE-B should be fixed by the day 40 scan: %+v", b)
	}
	if c := byID["CVE-C"]; c.FixedAt != nil || c.Image != "repo/web" {
		t.Errorf("CVE-C should still be open: %+v", c)
	}
	if d := byID["CVE-D"]; d.FixedAt == nil || !d.FixedAt.Equal(day(3)) || !d.FirstSeen.Before(periodFrom) {
		t.Errorf("CVE-D = %+v", d)
	}
}

func TestBuildSummary(t *testing.T) {
	s := Build(Input{
		ID: "PS-20261001-ABC123", GeneratedAt: time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC),
		Tool: report.Tool{Name: "scanproof", Version: "0.2.0"}, Period: testPeriod(),
		Policy: policy.Default(), StoreLocation: "file:///evidence/", Scans: sampleScans(),
	})

	c := s.Coverage
	if c.Scans != 7 || c.CIScans != 4 || c.RescanScans != 3 || c.Images != 6 || c.Repositories != 3 {
		t.Errorf("coverage = %+v", c)
	}
	if c.Pass != 4 || c.Warn != 2 || c.Fail != 1 || c.DaysWithRescans != 3 || c.DaysInPeriod != 92 {
		t.Errorf("coverage = %+v", c)
	}

	crit := s.remediation(model.SeverityCritical)
	if crit.Opened != 1 || crit.Fixed != 2 || crit.FixedInSLA != 2 || crit.OpenOverdue != 0 {
		t.Errorf("critical remediation = %+v", crit)
	}
	high := s.remediation(model.SeverityHigh)
	if high.Opened != 2 || high.Fixed != 1 || high.FixedInSLA != 0 || high.OpenOverdue != 1 || high.MedianDaysToFix != 39 {
		t.Errorf("high remediation = %+v", high)
	}
	if len(s.FixedLate) != 1 || s.FixedLate[0].ID != "CVE-B" {
		t.Errorf("fixed late = %+v", s.FixedLate)
	}
	if len(s.Overdue) != 1 || s.Overdue[0].ID != "CVE-C" {
		t.Errorf("overdue = %+v", s.Overdue)
	}
	if strings.Join(s.Exceptions.Applied, ",") != "EX-1" {
		t.Errorf("exceptions = %+v", s.Exceptions)
	}
	if len(s.Population) != 7 || s.Population[0].ReportID != "SR-A1" {
		t.Errorf("population should hold only in-period scans, oldest first: %+v", s.Population)
	}
	data, err := json.Marshal(s)
	if err != nil || !strings.Contains(string(data), `"population_count":7`) {
		t.Fatalf("json: %s %v", data, err)
	}
}

func TestLoadReadsOnlyResultsInRange(t *testing.T) {
	st, err := store.Open(context.Background(), "file://"+t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	docs := []report.Document{
		scanDoc("SR-OLD", "a:1", "sha256:1", periodFrom.AddDate(0, 0, -200), report.TriggerCI, policy.VerdictPass),
		scanDoc("SR-1", "a:1", "sha256:1", day(1), report.TriggerCI, policy.VerdictPass),
		scanDoc("SR-2", "a:1", "sha256:1", day(92), report.TriggerCI, policy.VerdictPass),
		scanDoc("SR-AFTER", "a:1", "sha256:1", periodTo.AddDate(0, 0, 1), report.TriggerCI, policy.VerdictPass),
	}
	putDocs(t, st, docs)
	if err := st.Put(context.Background(), store.ScanPrefix("SR-1", day(1))+"summary.md", []byte("x"), "text/markdown"); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(context.Background(), st, testPeriod())
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, l := range loaded {
		ids = append(ids, l.ReportID)
	}
	if strings.Join(ids, ",") != "SR-1,SR-2" {
		t.Fatalf("loaded %v", ids)
	}
	if !strings.HasSuffix(loaded[0].Location, store.ScanPrefix("SR-1", day(1))) {
		t.Errorf("location = %q", loaded[0].Location)
	}
}

func TestLoadRejectsCorruptResults(t *testing.T) {
	st, _ := store.Open(context.Background(), "file://"+t.TempDir())
	if err := st.Put(context.Background(), store.ScanPrefix("SR-BAD", day(1))+"results.json", []byte("{not json"), "application/json"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), st, testPeriod()); err == nil {
		t.Fatal("a corrupt results.json must not be skipped silently")
	}
}

func TestPopulationCSV(t *testing.T) {
	rows := []PopulationRow{{ReportID: "SR-1", ScannedAt: "2026-07-01 06:00:00 UTC", Image: "=cmd|calc", Verdict: "PASS"}}
	out, err := PopulationCSV(rows)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.HasPrefix(text, "report_id,scanned_at_utc,trigger,image,digest,verdict,violations,repository,commit,evidence\n") {
		t.Errorf("header = %q", strings.SplitN(text, "\n", 2)[0])
	}
	if !strings.Contains(text, "'=cmd|calc") {
		t.Error("cells that start with = must be neutralised so spreadsheets do not run them")
	}
}

func TestNewSummaryID(t *testing.T) {
	id, err := NewSummaryID(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || !strings.HasPrefix(id, "PS-20261001-") || len(id) != len("PS-20261001-ABC123") {
		t.Fatalf("got %q, %v", id, err)
	}
}
