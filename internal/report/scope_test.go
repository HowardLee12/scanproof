package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/exception"
)

func scopedDocument(t *testing.T) Document {
	t.Helper()
	list, err := exception.Parse([]byte(`
exceptions:
  - id: EX-GO
    finding: CVE-2022-48174
    package: busybox
    artifact: [alpine, "cr.example.com/mirror/*"]
    reason: Vendor image.
    expires: 2027-02-28
`))
	if err != nil {
		t.Fatal(err)
	}
	doc := sampleDocument(t)
	doc.Exceptions = Exceptions{Applied: list, Expired: []exception.Exception{}, Unused: []exception.Exception{}}
	return doc
}

func TestExceptionScopeInResults(t *testing.T) {
	data, err := json.Marshal(scopedDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"artifact":["alpine","cr.example.com/mirror/*"]`) {
		t.Errorf("results.json should list the scope: %s", data)
	}
}

func TestExceptionScopeInMarkdown(t *testing.T) {
	md := Markdown(scopedDocument(t))
	// Code spans keep two trailing * from pairing up as emphasis.
	want := "- Applied: EX-GO (CVE-2022-48174, only in `alpine`, `cr.example.com/mirror/*`, expires 2027-02-28)"
	if !strings.Contains(md, want) {
		t.Errorf("missing %q in:\n%s", want, md)
	}
	if md := Markdown(sampleDocument(t)); strings.Contains(md, "only in") {
		t.Error("an exception without a scope says nothing about one")
	}
}

func TestExceptionScopeInPDFView(t *testing.T) {
	rows := newPDFView(scopedDocument(t), "").ExceptionsApplied
	if len(rows) != 1 || rows[0][1] != "CVE-2022-48174 in busybox, only in alpine, cr.example.com/mirror/*" {
		t.Errorf("rows = %q", rows)
	}
}

// A stored results.json is read back by rescans and the period summary.
func TestScopeAndLimitsSurviveAResultsRoundTrip(t *testing.T) {
	doc := withLimits(malwareDocument(t))
	doc.Exceptions = scopedDocument(t).Exceptions
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Malware == nil || back.Malware.Limits == nil || *back.Malware.Limits != *doc.Malware.Limits {
		t.Errorf("limits = %+v", back.Malware)
	}
	if got := back.Exceptions.Applied[0].Artifact; len(got) != 2 || got[1] != "cr.example.com/mirror/*" {
		t.Errorf("artifact = %q", got)
	}
}
