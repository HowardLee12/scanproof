package summary

import (
	"bytes"
	encodingcsv "encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

const wantFindingsHeader = "image,artifact_type,id,package,severity,first_seen_utc,due_utc,status,closed_at_utc," +
	"days_open,sla_days,reopened,first_seen_report,last_seen_report,closed_by_reports"

func trackedByID(t *testing.T, tracked []TrackedFinding) map[string]TrackedFinding {
	t.Helper()
	out := map[string]TrackedFinding{}
	for _, f := range tracked {
		out[f.ID] = f
	}
	return out
}

func TestTrackRecordsTheReportsBehindEachFinding(t *testing.T) {
	byID := trackedByID(t, track(regressionScans(), policy.Default()))
	cases := []struct {
		id, first, last, closedBy, artifactType string
		reopened                                int
	}{
		// fixed by a new digest of the same image name
		{"CVE-A", "SR-A1", "SR-A1", "SR-A2", model.ArtifactContainerImage, 0},
		// staging is clean from day 1 but prod keeps it until day 6, when
		// both scans of the day no longer report it
		{"CVE-U1", "SR-UP1", "SR-UP5", "SR-UP6;SR-US6", model.ArtifactContainerImage, 0},
		// came back on day 30: first seen stays SR-R1, closing is the latest
		{"CVE-R1", "SR-R1", "SR-R4", "SR-R5", model.ArtifactContainerImage, 1},
		{"CVE-AC", "SR-AC1", "SR-AC1", "SR-AC2", model.ArtifactContainerImage, 0},
		{"CVE-C", "SR-C1", "SR-C2", "", model.ArtifactContainerImage, 0},
		{"CVE-DV", "SR-D1", "SR-D2", "", model.ArtifactDirectory, 0},
		{"CVE-D", "SR-W0", "SR-W1", "SR-W2", model.ArtifactContainerImage, 0},
	}
	for _, c := range cases {
		f, ok := byID[c.id]
		if !ok {
			t.Fatalf("%s not tracked", c.id)
		}
		got := []string{f.FirstSeenReport, f.LastSeenReport, strings.Join(f.ClosedBy, ";"), f.ArtifactType}
		want := []string{c.first, c.last, c.closedBy, c.artifactType}
		if strings.Join(got, "|") != strings.Join(want, "|") || f.Reopened != c.reopened {
			t.Errorf("%s: reports %v reopened %d, want %v reopened %d", c.id, got, f.Reopened, want, c.reopened)
		}
	}
}

func TestSameDayScanThatStillHasTheFindingIsItsLastSighting(t *testing.T) {
	crit := finding("CVE-P", "openssl", model.SeverityCritical, "3.0.15")
	rescan := report.TriggerRescan
	scans := loaded(
		scanDoc("SR-S1", "repo/app:2", "sha256:s", day(1), rescan, policy.VerdictPass),
		scanDoc("SR-P1", "repo/app:1", "sha256:p", day(1).Add(time.Minute), rescan, policy.VerdictWarn, crit),
		scanDoc("SR-S2", "repo/app:2", "sha256:s", day(1).Add(2*time.Minute), rescan, policy.VerdictPass),
		scanDoc("SR-P2", "repo/app:1", "sha256:p", day(1).Add(3*time.Minute), rescan, policy.VerdictWarn, crit),
		scanDoc("SR-S3", "repo/app:2", "sha256:s", day(2), rescan, policy.VerdictPass),
	)
	f := track(scans, policy.Default())[0]
	if f.FirstSeenReport != "SR-P1" || f.LastSeenReport != "SR-P2" || strings.Join(f.ClosedBy, ";") != "SR-S3" {
		t.Fatalf("union day: %+v", f)
	}
}

// csvRows parses findings.csv into maps keyed by column, indexed by ID.
func csvRows(t *testing.T, data []byte) ([]string, map[string]map[string]string, []string) {
	t.Helper()
	records, err := encodingcsv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header := records[0]
	byID, order := map[string]map[string]string{}, []string{}
	for _, rec := range records[1:] {
		row := map[string]string{}
		for i, name := range header {
			row[name] = rec[i]
		}
		byID[row["id"]] = row
		order = append(order, row["id"])
	}
	return header, byID, order
}

func TestFindingsCSV(t *testing.T) {
	s := regressionSummary()
	data, err := FindingsCSV(s.Findings)
	if err != nil {
		t.Fatal(err)
	}
	header, rows, order := csvRows(t, data)
	if strings.Join(header, ",") != wantFindingsHeader {
		t.Fatalf("header = %v", header)
	}
	want := map[string]string{
		"CVE-A": "repo/api,container_image,CVE-A,openssl,CRITICAL,2026-07-01T06:00:00Z,2026-07-16T06:00:00Z,fixed_in_sla," +
			"2026-07-05T06:00:00Z,4.0,15,0,SR-A1,SR-A1,SR-A2",
		"CVE-U1": "repo/union,container_image,CVE-U1,openssl,CRITICAL,2026-07-01T06:00:00Z,2026-07-16T06:00:00Z,fixed_in_sla," +
			"2026-07-06T06:00:00Z,5.0,15,0,SR-UP1,SR-UP5,SR-UP6;SR-US6",
		"CVE-R1": "repo/reopen,container_image,CVE-R1,curl,HIGH,2026-07-03T06:00:00Z,2026-08-02T06:00:00Z,fixed_late," +
			"2026-08-19T06:00:00Z,47.0,30,1,SR-R1,SR-R4,SR-R5",
		"CVE-AC": "repo/accept,container_image,CVE-AC,busybox,CRITICAL,2026-07-07T06:00:00Z,2026-07-22T06:00:00Z,accepted," +
			"2026-07-09T06:00:00Z,2.0,15,0,SR-AC1,SR-AC1,SR-AC2",
		"CVE-NF": "repo/accept,container_image,CVE-NF,zlib,HIGH,2026-07-07T06:00:00Z,2026-08-06T06:00:00Z,no_longer_fixable," +
			"2026-07-09T06:00:00Z,2.0,30,0,SR-AC1,SR-AC1,SR-AC2",
		"CVE-C": "repo/web,container_image,CVE-C,libxml2,HIGH,2026-07-10T06:00:00Z,2026-08-09T06:00:00Z,open_overdue," +
			",82.8,30,0,SR-C1,SR-C2,",
		"CVE-DV": "dir:model-env,directory,CVE-DV,urllib3,MEDIUM,2026-07-02T06:00:00Z,2026-09-30T06:00:00Z,open_overdue," +
			",90.8,90,0,SR-D1,SR-D2,",
		"CVE-LT": "repo/late,container_image,CVE-LT,nghttp2,HIGH,2026-09-23T06:00:00Z,2026-10-23T06:00:00Z,open_in_sla," +
			",7.8,30,0,SR-L1,SR-L1,",
	}
	for id, line := range want {
		row, ok := rows[id]
		if !ok {
			t.Errorf("%s missing from findings.csv", id)
			continue
		}
		got := make([]string, 0, len(header))
		for _, name := range header {
			got = append(got, row[name])
		}
		if strings.Join(got, ",") != line {
			t.Errorf("%s:\n got %s\nwant %s", id, strings.Join(got, ","), line)
		}
	}
	// CVE-O1 opened and closed before the period, so it is not listed.
	wantOrder := "CVE-LG,CVE-D,CVE-A,CVE-B,CVE-U1,CVE-DV,CVE-R1,CVE-AC,CVE-NF,CVE-C,CVE-LT"
	if strings.Join(order, ",") != wantOrder {
		t.Errorf("order = %v, want %s", order, wantOrder)
	}
}

// TestFindingsAddUpToTheRemediationTable checks that findings.csv lists
// exactly the findings counted in the remediation table.
func TestFindingsAddUpToTheRemediationTable(t *testing.T) {
	s := regressionSummary()
	counts := map[string]map[string]int{}
	for _, f := range s.Findings {
		if counts[f.Severity] == nil {
			counts[f.Severity] = map[string]int{}
		}
		counts[f.Severity][f.Status]++
	}
	for _, r := range s.Remediation {
		c := counts[r.Severity.String()]
		if c[StatusFixedInSLA] != r.FixedInSLA || c[StatusFixedLate] != r.Fixed-r.FixedInSLA ||
			c[StatusAccepted]+c[StatusNoLongerFixable] != r.ClosedOther ||
			c[StatusOpenInSLA] != r.OpenInSLA || c[StatusOpenOverdue] != r.OpenOverdue {
			t.Errorf("%s: findings %v do not match remediation %+v", r.Severity, c, r)
		}
	}
	data, err := json.Marshal(s)
	if err != nil || !strings.Contains(string(data), `"findings_count":11`) || strings.Contains(string(data), "first_seen_report") {
		t.Fatalf("summary.json should count the rows without listing them: %s %v", data, err)
	}
}

func TestNeutralize(t *testing.T) {
	cases := map[string]string{
		"=1+1":            "'=1+1",
		"+1":              "'+1",
		"-1":              "'-1",
		"@SUM(A1)":        "'@SUM(A1)",
		"\tcmd":           "'\tcmd",
		"\rcmd":           "'\rcmd",
		"":                "",
		"repo/api":        "repo/api",
		"SR-1;SR-2":       "SR-1;SR-2",
		"2026-07-01":      "2026-07-01",
		" =not a formula": " =not a formula",
	}
	for in, want := range cases {
		if got := neutralize(in); got != want {
			t.Errorf("neutralize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindingsCSVNeutralizesFormulas(t *testing.T) {
	rows := []FindingRow{{
		Image: "=HYPERLINK(\"http://x\",\"y\")", ArtifactType: "container_image", ID: "+CVE", Package: "@pkg",
		Severity: "HIGH", Status: StatusOpenInSLA, FirstSeenReport: "-SR", LastSeenReport: "\tSR", ClosedBy: []string{"\rSR"},
	}}
	data, err := FindingsCSV(rows)
	if err != nil {
		t.Fatal(err)
	}
	records, err := encodingcsv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(records[1]) != len(records[0]) {
		t.Fatalf("records = %q", records)
	}
	for _, i := range []int{0, 2, 3, 12, 13, 14} {
		if !strings.HasPrefix(records[1][i], "'") {
			t.Errorf("column %s = %q, want it neutralised", records[0][i], records[1][i])
		}
	}
}

func TestReopenedFindingThatIsOpenAgainHasNoClosingReports(t *testing.T) {
	crit := finding("CVE-Q", "openssl", model.SeverityCritical, "3.0.15")
	accepted := crit
	accepted.ExceptionID = "EX-2"
	ci := report.TriggerCI
	scans := loaded(
		scanDoc("SR-1", "repo/app:1", "sha256:1", day(1), ci, policy.VerdictWarn, crit),
		scanDoc("SR-2", "repo/app:2", "sha256:2", day(2), ci, policy.VerdictPass),
		scanDoc("SR-3", "repo/app:1", "sha256:1", day(4), ci, policy.VerdictWarn, crit),
		// accepted by an exception, then back once the exception expires
		scanDoc("SR-4", "repo/app:1", "sha256:1", day(6), ci, policy.VerdictPass, accepted),
		scanDoc("SR-5", "repo/app:1", "sha256:1", day(9), ci, policy.VerdictWarn, crit),
	)
	if f := track(scans[:4], policy.Default())[0]; f.Resolution != ResolutionAccepted || strings.Join(f.ClosedBy, ";") != "SR-4" || f.Reopened != 1 {
		t.Fatalf("before it came back: %+v", f)
	}
	s := Build(Input{GeneratedAt: periodTo.AddDate(0, 0, 2), Period: testPeriod(), Policy: policy.Default(), Scans: scans})
	data, err := FindingsCSV(s.Findings)
	if err != nil {
		t.Fatal(err)
	}
	_, rows, _ := csvRows(t, data)
	row := rows["CVE-Q"]
	got := []string{row["status"], row["closed_at_utc"], row["closed_by_reports"], row["reopened"], row["first_seen_report"], row["last_seen_report"], row["first_seen_utc"]}
	want := []string{StatusOpenOverdue, "", "", "2", "SR-1", "SR-5", "2026-07-01T06:00:00Z"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
