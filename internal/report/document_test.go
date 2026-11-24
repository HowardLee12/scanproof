package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
)

func TestBuildSummarisesFindings(t *testing.T) {
	doc := sampleDocument(t)

	if doc.Schema != SchemaVersion || doc.ReportID != "SR-20261124-7F3A9C" {
		t.Errorf("header wrong: %s %s", doc.Schema, doc.ReportID)
	}
	crit := doc.Summary.Count(model.SeverityCritical)
	if crit.Total != 3 || crit.Fixable != 3 || crit.Accepted != 1 {
		t.Errorf("critical counts = %+v", crit)
	}
	// 3 fixable Criticals, one accepted by EX-2026-004.
	if doc.Summary.Violations != 2 || doc.Verdict != policy.VerdictWarn {
		t.Errorf("violations %d, verdict %s", doc.Summary.Violations, doc.Verdict)
	}
	if len(doc.Exceptions.Applied) != 1 || len(doc.Exceptions.Unused) != 0 {
		t.Errorf("exceptions = %+v", doc.Exceptions)
	}
	if doc.Policy.Source != "built-in default" || len(doc.Policy.Rules) != 2 {
		t.Errorf("policy info = %+v", doc.Policy)
	}
}

func TestBuildSortsMostSevereFirst(t *testing.T) {
	doc := sampleDocument(t)
	for i := 1; i < len(doc.Vulnerabilities); i++ {
		if doc.Vulnerabilities[i].Severity > doc.Vulnerabilities[i-1].Severity {
			t.Fatalf("finding %d is more severe than the one before it", i)
		}
	}
	if !doc.Vulnerabilities[0].Violation {
		t.Error("violations should come before accepted findings of the same severity")
	}
}

func TestDocumentJSONUsesNamesAndEmptyLists(t *testing.T) {
	doc := sampleDocument(t)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"verdict":"WARN"`, `"severity":"CRITICAL"`, `"secrets":[]`, `"expires":"2027-02-28"`} {
		if !strings.Contains(text, want) {
			t.Errorf("results.json is missing %s", want)
		}
	}
}

func TestSummaryCountForMissingSeverity(t *testing.T) {
	if c := (Summary{}).Count(model.SeverityHigh); c.Total != 0 || c.Severity != model.SeverityHigh {
		t.Fatalf("got %+v", c)
	}
}
