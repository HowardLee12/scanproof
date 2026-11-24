package model

import (
	"encoding/json"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL": SeverityCritical,
		"high":     SeverityHigh,
		" Medium ": SeverityMedium,
		"LOW":      SeverityLow,
		"UNKNOWN":  SeverityUnknown,
	}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil {
			t.Fatalf("ParseSeverity(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseSeverityRejectsUnknownText(t *testing.T) {
	if _, err := ParseSeverity("SEVERE"); err == nil {
		t.Fatal("expected an error for an unrecognised severity")
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(SeverityCritical > SeverityHigh && SeverityHigh > SeverityMedium &&
		SeverityMedium > SeverityLow && SeverityLow > SeverityUnknown) {
		t.Fatal("severities must order from unknown to critical")
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	data, err := json.Marshal(struct {
		S Severity `json:"s"`
	}{SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"s":"HIGH"}` {
		t.Fatalf("unexpected JSON %s", data)
	}
	var out struct {
		S Severity `json:"s"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.S != SeverityHigh {
		t.Fatalf("round trip gave %v", out.S)
	}
}

func TestVulnerabilityFixable(t *testing.T) {
	if (Vulnerability{FixedVersion: ""}).Fixable() {
		t.Error("a vulnerability without a fixed version is not fixable")
	}
	if !(Vulnerability{FixedVersion: "1.2.3"}).Fixable() {
		t.Error("a vulnerability with a fixed version is fixable")
	}
}
