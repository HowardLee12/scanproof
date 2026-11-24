package policy

import (
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/model"
)

var now = time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)

func vuln(id string, sev model.Severity, fixed string) model.Vulnerability {
	return model.Vulnerability{ID: id, Package: "pkg", Severity: sev, FixedVersion: fixed}
}

func mustExceptions(t *testing.T, doc string) []exception.Exception {
	t.Helper()
	list, err := exception.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestCleanScanPasses(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityHigh, "1.1")}}
	ev := Evaluate(res, Default(), nil, now)
	if ev.Verdict != VerdictPass {
		t.Fatalf("verdict = %s", ev.Verdict)
	}
	for _, r := range ev.Rules {
		if !r.Passed {
			t.Errorf("rule %q should pass", r.Name)
		}
	}
}

func TestFixableCriticalWarnsInWarnModeAndFailsInEnforceMode(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityCritical, "1.1")}}

	warn := Evaluate(res, Default(), nil, now)
	if warn.Verdict != VerdictWarn || !warn.Vulnerabilities[0].Violation {
		t.Fatalf("warn mode: verdict %s, violation %v", warn.Verdict, warn.Vulnerabilities[0].Violation)
	}
	if warn.Rules[0].Found != 1 || warn.Rules[0].Passed {
		t.Errorf("rule should report 1 violation: %+v", warn.Rules[0])
	}

	enforce := Evaluate(res, Default().WithMode(ModeEnforce), nil, now)
	if enforce.Verdict != VerdictFail {
		t.Fatalf("enforce mode: verdict %s", enforce.Verdict)
	}
}

func TestUnfixableCriticalOnlyCountsWhenFixableOnlyIsOff(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityCritical, "")}}
	if ev := Evaluate(res, Default(), nil, now); ev.Verdict != VerdictPass {
		t.Errorf("an unfixable finding is not a violation by default, got %s", ev.Verdict)
	}
	strict := Default()
	strict.FixableOnly = false
	if ev := Evaluate(res, strict, nil, now); ev.Verdict != VerdictWarn {
		t.Errorf("with fixable_only off it is a violation, got %s", ev.Verdict)
	}
}

func TestLowerThresholdCatchesHigh(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityHigh, "2.0")}}
	p := Default()
	p.MinSeverity = model.SeverityHigh
	if ev := Evaluate(res, p, nil, now); ev.Verdict != VerdictWarn {
		t.Fatalf("verdict = %s", ev.Verdict)
	}
}

func TestActiveExceptionAcceptsFinding(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityCritical, "1.1")}}
	excs := mustExceptions(t, "exceptions:\n  - {id: EX-1, finding: CVE-1, reason: r, expires: 2027-01-31}\n")

	ev := Evaluate(res, Default(), excs, now)
	if ev.Verdict != VerdictPass {
		t.Fatalf("verdict = %s", ev.Verdict)
	}
	f := ev.Vulnerabilities[0]
	if f.ExceptionID != "EX-1" || !f.Accepted() || f.Violation {
		t.Errorf("finding should be accepted by EX-1: %+v", f)
	}
	if len(ev.Applied) != 1 || len(ev.Expired) != 0 || len(ev.Unused) != 0 {
		t.Errorf("applied %d, expired %d, unused %d", len(ev.Applied), len(ev.Expired), len(ev.Unused))
	}
}

func TestExpiredExceptionStopsApplying(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityCritical, "1.1")}}
	excs := mustExceptions(t, "exceptions:\n  - {id: EX-1, finding: CVE-1, reason: r, expires: 2026-11-23}\n")

	ev := Evaluate(res, Default(), excs, now)
	if ev.Verdict != VerdictWarn || ev.Vulnerabilities[0].Accepted() {
		t.Fatalf("an expired exception must not accept the finding: %s", ev.Verdict)
	}
	if len(ev.Expired) != 1 || ev.Expired[0].ID != "EX-1" {
		t.Errorf("expired exception should be listed: %+v", ev.Expired)
	}
}

func TestUnusedExceptionIsListed(t *testing.T) {
	excs := mustExceptions(t, "exceptions:\n  - {id: EX-9, finding: CVE-9, reason: r, expires: 2027-01-31}\n")
	ev := Evaluate(model.ScanResult{}, Default(), excs, now)
	if len(ev.Unused) != 1 || ev.Unused[0].ID != "EX-9" {
		t.Fatalf("unused exceptions should be listed: %+v", ev.Unused)
	}
}

func TestSecretsAreViolationsUnlessAccepted(t *testing.T) {
	res := model.ScanResult{Secrets: []model.Secret{
		{RuleID: "aws-access-key-id", Severity: model.SeverityCritical},
		{RuleID: "github-pat", Severity: model.SeverityCritical, Target: "tests/token.txt"},
	}}
	excs := mustExceptions(t, "exceptions:\n  - {id: EX-2, finding: github-pat, path: tests/token.txt, reason: r, expires: 2027-01-31}\n")

	ev := Evaluate(res, Default(), excs, now)
	if ev.Verdict != VerdictWarn {
		t.Fatalf("verdict = %s", ev.Verdict)
	}
	if !ev.Secrets[0].Violation || ev.Secrets[1].Violation || ev.Secrets[1].ExceptionID != "EX-2" {
		t.Errorf("unexpected secret findings %+v", ev.Secrets)
	}
	if got := ev.Rules[1]; got.Found != 1 || got.Passed {
		t.Errorf("secret rule should count 1: %+v", got)
	}
}

func TestSecretsIgnoredWhenTurnedOff(t *testing.T) {
	res := model.ScanResult{Secrets: []model.Secret{{RuleID: "aws-access-key-id"}}}
	p := Default()
	p.BlockSecrets = false
	ev := Evaluate(res, p, nil, now)
	if ev.Verdict != VerdictPass || len(ev.Rules) != 1 {
		t.Fatalf("verdict %s with %d rules", ev.Verdict, len(ev.Rules))
	}
}

func TestRuleNamesDescribeThreshold(t *testing.T) {
	ev := Evaluate(model.ScanResult{}, Default(), nil, now)
	if ev.Rules[0].Name != "No open CRITICAL vulnerabilities with a fix available" {
		t.Errorf("rule name = %q", ev.Rules[0].Name)
	}
	p := Default()
	p.MinSeverity = model.SeverityHigh
	p.FixableOnly = false
	ev = Evaluate(model.ScanResult{}, p, nil, now)
	if ev.Rules[0].Name != "No open HIGH or CRITICAL vulnerabilities" {
		t.Errorf("rule name = %q", ev.Rules[0].Name)
	}
}

func TestEvaluateDoesNotModifyInput(t *testing.T) {
	res := model.ScanResult{Vulnerabilities: []model.Vulnerability{vuln("CVE-1", model.SeverityCritical, "1.1")}}
	before := res.Vulnerabilities[0]
	Evaluate(res, Default(), nil, now)
	if res.Vulnerabilities[0] != before {
		t.Fatal("Evaluate must not mutate the scan result")
	}
}

func TestMalwareDetectionsAreViolationsUnlessAccepted(t *testing.T) {
	res := model.ScanResult{Malware: &model.MalwareScan{Detections: []model.MalwareDetection{
		{Path: "/app/tests/eicar.com", Engine: "ClamAV", Signature: "Eicar-Test-Signature"},
		{Path: "/usr/bin/kworker", Engine: "YARA", Signature: "Linux_Miner"},
	}}}
	excs := mustExceptions(t, "exceptions:\n  - {id: EX-M, finding: Eicar-Test-Signature, path: app/tests/eicar.com, reason: r, expires: 2027-01-31}\n")
	ev := Evaluate(res, Default(), excs, now)
	if ev.Verdict != VerdictWarn || len(ev.Malware) != 2 {
		t.Fatalf("verdict %s, %d findings", ev.Verdict, len(ev.Malware))
	}
	if ev.Malware[0].ExceptionID != "EX-M" || ev.Malware[0].Violation || !ev.Malware[1].Violation {
		t.Errorf("findings = %+v", ev.Malware)
	}
	rule := ev.Rules[len(ev.Rules)-1]
	if rule.Name != "No malware detections" || rule.Found != 1 || rule.Passed {
		t.Errorf("rule = %+v", rule)
	}
}

func TestNoMalwareRuleWithoutAMalwareScan(t *testing.T) {
	for _, r := range Evaluate(model.ScanResult{}, Default(), nil, now).Rules {
		if r.Name == "No malware detections" {
			t.Fatal("the malware rule only applies when a malware scan ran")
		}
	}
}

func TestMalwareCanBeReportOnly(t *testing.T) {
	p, err := Parse([]byte("fail_on:\n  malware: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := model.ScanResult{Malware: &model.MalwareScan{Detections: []model.MalwareDetection{{Path: "/x", Signature: "S"}}}}
	if ev := Evaluate(res, p, nil, now); ev.Verdict != VerdictPass || ev.Malware[0].Violation {
		t.Fatalf("with malware: false a detection is reported but not a violation: %+v", ev)
	}
}
