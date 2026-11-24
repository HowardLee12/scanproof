package exception

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
)

const validYAML = `
exceptions:
  - id: EX-2026-004
    finding: CVE-2023-45853
    package: zlib1g
    reason: MiniZip is not built into Debian's zlib1g; no fixed version is available.
    approved_by: security-lead
    expires: 2027-02-28
  - id: EX-2026-005
    finding: aws-access-key-id
    path: tests/fixtures/fake.ini
    reason: Documented example key in a test fixture.
    expires: "2026-12-31"
`

func TestParseValidFile(t *testing.T) {
	list, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d exceptions, want 2", len(list))
	}
	first := list[0]
	if first.ID != "EX-2026-004" || first.Finding != "CVE-2023-45853" || first.Package != "zlib1g" ||
		first.ApprovedBy != "security-lead" || first.Expires.String() != "2027-02-28" {
		t.Errorf("unexpected exception %+v", first)
	}
}

func TestParseEmptyFileHasNoExceptions(t *testing.T) {
	list, err := Parse([]byte(""))
	if err != nil || len(list) != 0 {
		t.Fatalf("got %v, %v", list, err)
	}
}

func TestParseRejectsInvalidEntries(t *testing.T) {
	cases := map[string]string{
		"missing id":      "exceptions:\n  - finding: CVE-1\n    reason: r\n    expires: 2027-01-01\n",
		"missing finding": "exceptions:\n  - id: A\n    reason: r\n    expires: 2027-01-01\n",
		"missing reason":  "exceptions:\n  - id: A\n    finding: CVE-1\n    expires: 2027-01-01\n",
		"missing expires": "exceptions:\n  - id: A\n    finding: CVE-1\n    reason: r\n",
		"bad date":        "exceptions:\n  - id: A\n    finding: CVE-1\n    reason: r\n    expires: next year\n",
		"duplicate id":    "exceptions:\n  - {id: A, finding: CVE-1, reason: r, expires: 2027-01-01}\n  - {id: A, finding: CVE-2, reason: r, expires: 2027-01-01}\n",
		"unknown field":   "exceptions:\n  - {id: A, finding: CVE-1, reason: r, expire: 2027-01-01}\n",
		"not yaml":        "exceptions: [",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestActiveThroughEndOfExpiryDay(t *testing.T) {
	list, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	ex := list[0]
	if !ex.Active(time.Date(2027, 2, 28, 23, 59, 59, 0, time.UTC)) {
		t.Error("an exception is valid for the whole expiry day")
	}
	if ex.Active(time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("an exception stops applying the day after it expires")
	}
}

func TestMatchesVulnerability(t *testing.T) {
	list, _ := Parse([]byte(validYAML))
	ex := list[0]
	if !ex.MatchesVulnerability(model.Vulnerability{ID: "cve-2023-45853", Package: "zlib1g"}) {
		t.Error("IDs should match regardless of case")
	}
	if ex.MatchesVulnerability(model.Vulnerability{ID: "CVE-2023-45853", Package: "minizip"}) {
		t.Error("a package-scoped exception must not match another package")
	}
	anyPackage := Exception{ID: "X", Finding: "CVE-1"}
	if !anyPackage.MatchesVulnerability(model.Vulnerability{ID: "CVE-1", Package: "openssl"}) {
		t.Error("an exception without a package matches the finding in any package")
	}
}

func TestMatchesSecretNeedsRuleAndPath(t *testing.T) {
	list, _ := Parse([]byte(validYAML))
	ex := list[1]
	if !ex.MatchesSecret(model.Secret{RuleID: "aws-access-key-id", Target: "tests/fixtures/fake.ini"}) {
		t.Error("the secret in the named file should match")
	}
	if !ex.MatchesSecret(model.Secret{RuleID: "aws-access-key-id", Target: "/tests/fixtures/fake.ini"}) {
		t.Error("a leading slash should not matter")
	}
	if ex.MatchesSecret(model.Secret{RuleID: "aws-access-key-id", Target: "config.ini"}) {
		t.Error("the same kind of secret in another file must not be accepted")
	}
	if ex.MatchesSecret(model.Secret{RuleID: "github-pat", Target: "tests/fixtures/fake.ini"}) {
		t.Error("a different rule must not match")
	}
	noPath := Exception{ID: "X", Finding: "aws-access-key-id"}
	if noPath.MatchesSecret(model.Secret{RuleID: "aws-access-key-id", Target: "config.ini"}) {
		t.Error("an exception without a path must never accept a secret")
	}
}

func TestParseRejectsPackageAndPathTogether(t *testing.T) {
	doc := "exceptions:\n  - {id: A, finding: CVE-1, package: p, path: f, reason: r, expires: 2027-01-01}\n"
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("package is for vulnerabilities and path is for secrets; both at once is a mistake")
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := Load(path)
	if err != nil || len(list) != 2 {
		t.Fatalf("got %d, %v", len(list), err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil ||
		!strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("expected an error naming the missing file, got %v", err)
	}
}

func TestExampleExceptionsAreValid(t *testing.T) {
	list, err := Load("../../examples/exceptions.yaml")
	if err != nil || len(list) != 2 {
		t.Fatalf("got %d exceptions, %v", len(list), err)
	}
}

func TestDateJSONRoundTrip(t *testing.T) {
	list, _ := Parse([]byte(validYAML))
	data, err := json.Marshal(list[0])
	if err != nil {
		t.Fatal(err)
	}
	var back Exception
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Expires.String() != "2027-02-28" || back.ID != "EX-2026-004" {
		t.Fatalf("round trip lost data: %+v", back)
	}
	var bad Date
	if err := bad.UnmarshalText([]byte("soon")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestMatchesMalwareNeedsSignatureAndPath(t *testing.T) {
	ex := Exception{ID: "EX-M", Finding: "Eicar-Test-Signature", Path: "app/tests/eicar.com"}
	if !ex.MatchesMalware(model.MalwareDetection{Path: "/app/tests/eicar.com", Signature: "Eicar-Test-Signature"}) {
		t.Error("the detection in the named file should match")
	}
	if ex.MatchesMalware(model.MalwareDetection{Path: "/usr/bin/eicar", Signature: "Eicar-Test-Signature"}) {
		t.Error("the same signature in another file must not match")
	}
	if (Exception{ID: "X", Finding: "Eicar-Test-Signature"}).MatchesMalware(model.MalwareDetection{Path: "/a", Signature: "Eicar-Test-Signature"}) {
		t.Error("a malware exception without a path must never match")
	}
}
