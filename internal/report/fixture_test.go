package report

import (
	"os"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

var testNow = time.Date(2026, 11, 24, 8, 16, 48, 0, time.UTC)

const testExceptions = `
exceptions:
  - id: EX-2026-004
    finding: CVE-2022-48174
    package: busybox
    reason: Shell is not reachable by the application.
    approved_by: security-lead
    expires: 2027-02-28
  - id: EX-2026-001
    finding: CVE-2000-0001
    reason: Old finding that was fixed.
    expires: 2026-01-31
`

// sampleDocument builds a report from the real Trivy fixture.
func sampleDocument(t *testing.T) Document {
	t.Helper()
	f, err := os.Open("../../testdata/trivy-alpine-3.18.0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := trivy.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	excs, err := exception.Parse([]byte(testExceptions))
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.Default()
	ev := policy.Evaluate(res, pol, excs, testNow)
	return Build(Input{
		ReportID:     "SR-20261124-7F3A9C",
		GeneratedAt:  testNow,
		Tool:         Tool{Name: "scanproof", Version: "0.1.0"},
		Result:       res,
		Evaluation:   ev,
		Policy:       pol,
		PolicySource: policy.BuiltinSource(),
		Context: cicontext.Context{
			Provider:   "GitHub Actions",
			Repository: "example-org/example-api",
			Commit:     "3e1f9a2c7b4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f",
			Branch:     "main",
			RunURL:     "https://github.com/example-org/example-api/actions/runs/1",
		},
	})
}
