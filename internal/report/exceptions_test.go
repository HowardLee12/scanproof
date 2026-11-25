package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

const excHash = "4f2a7d0c9b8e6f5a4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e"

// documentWithExceptionsFile is the sample report built with an exceptions
// file, n of whose exceptions apply only to other artifacts.
func documentWithExceptionsFile(t *testing.T, n int) Document {
	t.Helper()
	base := sampleDocument(t)
	out := make([]exception.Exception, 0, n)
	for i := range n {
		out = append(out, exception.Exception{ID: fmt.Sprintf("EX-%02d", i+1), Artifact: exception.Artifacts{"other"}})
	}
	ev := policy.Evaluation{Vulnerabilities: base.Vulnerabilities, Rules: base.Policy.Rules, Verdict: base.Verdict, OutOfScope: out}
	return Build(Input{
		ReportID: base.ReportID, GeneratedAt: base.GeneratedAt, Tool: base.Tool,
		Result: fixtureResult(t), Evaluation: ev, Policy: policy.Default(), PolicySource: policy.BuiltinSource(),
		ExceptionsSource: exception.Source{Path: ".scanproof/exceptions.yaml", SHA256: excHash},
	})
}

func TestExceptionsFileInResults(t *testing.T) {
	data, err := json.Marshal(documentWithExceptionsFile(t, 2).Exceptions)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"source":".scanproof/exceptions.yaml"`, `"sha256":"` + excHash + `"`,
		`"out_of_scope":{"count":2,"ids":["EX-01","EX-02"]}`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %s in %s", want, data)
		}
	}
	// Without an exceptions file, nothing new is written.
	data, _ = json.Marshal(sampleDocument(t).Exceptions)
	if strings.Contains(string(data), "source") || strings.Contains(string(data), "out_of_scope") {
		t.Errorf("unexpected fields: %s", data)
	}
}

func TestManyOutOfScopeExceptionsAreOnlyCounted(t *testing.T) {
	oos := documentWithExceptionsFile(t, maxOutOfScopeIDs+1).Exceptions.OutOfScope
	if oos == nil || oos.Count != maxOutOfScopeIDs+1 || len(oos.IDs) != 0 {
		t.Fatalf("out of scope = %+v", oos)
	}
}

func TestExceptionsFileInMarkdown(t *testing.T) {
	md := Markdown(documentWithExceptionsFile(t, 2))
	for _, want := range []string{
		"2 exceptions in the file apply only to other images or directories (EX-01, EX-02).",
		"· exceptions: .scanproof/exceptions.yaml (sha256:4f2a7d0c9b8e…)</sub>",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
	if md := Markdown(sampleDocument(t)); strings.Contains(md, "exceptions:") || strings.Contains(md, "other images") {
		t.Error("without an exceptions file the summary says nothing about one")
	}
}

func TestExceptionsFileInPDFView(t *testing.T) {
	v := newPDFView(documentWithExceptionsFile(t, 1), "")
	rows := map[string]string{}
	for _, r := range v.IntegrityRows {
		rows[r.Label] = r.Value
	}
	if rows["Exceptions"] != ".scanproof/exceptions.yaml" || rows["Exceptions SHA-256"] != excHash {
		t.Errorf("integrity rows = %+v", v.IntegrityRows)
	}
	if v.ExceptionsOutOfScope != "1 exception in the file applies only to other images or directories (EX-01)." {
		t.Errorf("out of scope = %q", v.ExceptionsOutOfScope)
	}
	if !strings.Contains(string(reportTemplate), "d.exceptions_out_of_scope") {
		t.Error("the PDF template should show it")
	}
}

func fixtureResult(t *testing.T) model.ScanResult {
	t.Helper()
	data, err := os.ReadFile("../../testdata/trivy-alpine-3.18.0.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := trivy.ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
