package summary

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
	"github.com/HowardLee12/scanproof/internal/store"
)

var periodFrom = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
var periodTo = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)

func day(n int) time.Time {
	return periodFrom.AddDate(0, 0, n-1).Add(6 * time.Hour)
}

func finding(id, pkg string, sev model.Severity, fixed string) policy.VulnerabilityFinding {
	return policy.VulnerabilityFinding{Vulnerability: model.Vulnerability{ID: id, Package: pkg, Severity: sev, FixedVersion: fixed}}
}

func scanDoc(id, ref, digest string, at time.Time, trigger string, verdict policy.Verdict, vulns ...policy.VulnerabilityFinding) report.Document {
	return report.Document{
		Schema:          report.SchemaVersion,
		ReportID:        id,
		GeneratedAt:     at,
		ScannedAt:       at,
		Trigger:         trigger,
		Verdict:         verdict,
		Image:           model.Image{Reference: ref, Digest: digest},
		Vulnerabilities: vulns,
		Secrets:         []policy.SecretFinding{},
		Exceptions:      report.Exceptions{Applied: []exception.Exception{}, Expired: []exception.Exception{}},
	}
}

// sampleScans tells a small story over Q3 2026:
//   - api: a Critical fixed in 4 days, a High fixed in 39 days (late)
//   - web: a High found on day 10 and still open at the end (overdue)
//   - worker: a Critical first seen 10 days before the period and fixed on
//     day 3, inside its 15-day SLA
func sampleScans() []Loaded {
	critA := finding("CVE-A", "openssl", model.SeverityCritical, "3.0.15")
	highB := finding("CVE-B", "curl", model.SeverityHigh, "8.9.1")
	highC := finding("CVE-C", "libxml2", model.SeverityHigh, "2.13.4")
	critD := finding("CVE-D", "glibc", model.SeverityCritical, "2.36-9")
	low := finding("CVE-L", "less", model.SeverityLow, "1.0")
	unfixable := finding("CVE-U", "zlib", model.SeverityCritical, "")
	accepted := finding("CVE-X", "busybox", model.SeverityCritical, "1.36.1")
	accepted.ExceptionID = "EX-1"

	docs := []report.Document{
		scanDoc("SR-W0", "repo/worker:1", "sha256:w1", periodFrom.AddDate(0, 0, -10), report.TriggerCI, policy.VerdictWarn, critD),
		scanDoc("SR-A1", "repo/api:1", "sha256:a1", day(1), report.TriggerCI, policy.VerdictWarn, critA, highB, low, unfixable, accepted),
		scanDoc("SR-W1", "repo/worker:1", "sha256:w1", day(2), report.TriggerRescan, policy.VerdictWarn, critD),
		scanDoc("SR-W2", "repo/worker:2", "sha256:w2", day(3), report.TriggerCI, policy.VerdictPass),
		scanDoc("SR-A2", "repo/api:2", "sha256:a2", day(5), report.TriggerCI, policy.VerdictPass, highB),
		scanDoc("SR-C1", "repo/web:1", "sha256:c1", day(10), report.TriggerCI, policy.VerdictFail, highC),
		scanDoc("SR-A3", "repo/api:3", "sha256:a3", day(40), report.TriggerRescan, policy.VerdictPass),
		scanDoc("SR-C2", "repo/web:1", "sha256:c1", day(88), report.TriggerRescan, policy.VerdictPass, highC),
	}
	docs[1].Exceptions.Applied = []exception.Exception{{ID: "EX-1"}}
	out := make([]Loaded, 0, len(docs))
	for _, d := range docs {
		out = append(out, Loaded{Document: d, Location: "file:///evidence/" + d.ReportID + "/"})
	}
	return out
}

func putDocs(t *testing.T, st store.Store, docs []report.Document) {
	t.Helper()
	for _, d := range docs {
		if err := writeDoc(context.Background(), st, d); err != nil {
			t.Fatal(err)
		}
	}
}

func writeDoc(ctx context.Context, st store.Store, d report.Document) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return st.Put(ctx, store.ScanPrefix(d.ReportID, d.GeneratedAt)+"results.json", data, "application/json")
}
