package trivy

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
)

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseImageReport(t *testing.T) {
	res, err := Parse(openFixture(t, "trivy-alpine-3.18.0.json"))
	if err != nil {
		t.Fatal(err)
	}

	if got := len(res.Vulnerabilities); got != 49 {
		t.Fatalf("got %d vulnerabilities, want 49", got)
	}
	counts := map[model.Severity]int{}
	for _, v := range res.Vulnerabilities {
		counts[v.Severity]++
	}
	want := map[model.Severity]int{
		model.SeverityCritical: 3, model.SeverityHigh: 6, model.SeverityMedium: 26, model.SeverityLow: 14,
	}
	for sev, n := range want {
		if counts[sev] != n {
			t.Errorf("%v: got %d, want %d", sev, counts[sev], n)
		}
	}

	img := res.Image
	if img.Reference != "alpine:3.18.0" {
		t.Errorf("reference = %q", img.Reference)
	}
	if img.Digest != "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11" {
		t.Errorf("digest = %q", img.Digest)
	}
	if img.OS != "alpine 3.18.0" || img.SizeBytes != 7617536 || img.Layers != 1 {
		t.Errorf("unexpected image metadata %+v", img)
	}
	if img.Created == nil || img.Created.Year() != 2023 {
		t.Errorf("created = %v", img.Created)
	}
	if res.Scanner.Name != "trivy" || res.Scanner.Version != "0.76.2" {
		t.Errorf("scanner = %+v", res.Scanner)
	}
	if res.ScannedAt.IsZero() {
		t.Error("scan time missing")
	}
}

func TestParseMapsVulnerabilityFields(t *testing.T) {
	res, err := Parse(openFixture(t, "trivy-alpine-3.18.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var found *model.Vulnerability
	for i := range res.Vulnerabilities {
		if res.Vulnerabilities[i].ID == "CVE-2022-48174" {
			found = &res.Vulnerabilities[i]
			break
		}
	}
	if found == nil {
		t.Fatal("CVE-2022-48174 not found")
	}
	if found.Package != "busybox" || found.InstalledVersion != "1.36.0-r9" || found.FixedVersion != "1.36.1-r1" {
		t.Errorf("package fields wrong: %+v", found)
	}
	if found.Severity != model.SeverityCritical || found.CVSS != 9.8 {
		t.Errorf("severity/cvss wrong: %v %v", found.Severity, found.CVSS)
	}
	if found.ScannerStatus != "fixed" || !strings.HasPrefix(found.URL, "https://") || found.Title == "" {
		t.Errorf("metadata wrong: %+v", found)
	}
	if found.LayerDiffID == "" || found.Target == "" {
		t.Errorf("location missing: %+v", found)
	}
}

func TestParseSecretsNeverKeepsMatchedText(t *testing.T) {
	res, err := Parse(openFixture(t, "trivy-secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("got %d secrets, want 2", len(res.Secrets))
	}
	s := res.Secrets[0]
	if s.RuleID != "aws-access-key-id" || s.Severity != model.SeverityCritical || s.Line != 1 || s.Target != "config.ini" {
		t.Errorf("unexpected secret %+v", s)
	}
}

func TestParseRejectsInvalidJSON(t *testing.T) {
	if _, err := Parse(strings.NewReader("not json")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseRejectsUnsupportedSchema(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"SchemaVersion": 1}`)); err == nil {
		t.Fatal("expected an error for schema version 1")
	}
}

func TestParseVersion(t *testing.T) {
	info, err := ParseVersion(openFixture(t, "trivy-version.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.76.2" {
		t.Errorf("version = %q", info.Version)
	}
	want := time.Date(2026, 11, 24, 1, 5, 31, 0, time.UTC)
	if info.DBUpdatedAt == nil || !info.DBUpdatedAt.Truncate(time.Second).Equal(want) {
		t.Errorf("db updated = %v, want %v", info.DBUpdatedAt, want)
	}
}

func TestPickCVSSPrefersSeveritySource(t *testing.T) {
	cvss := map[string]cvssEntry{"nvd": {V3Score: 9.8}, "redhat": {V3Score: 7.5}}
	if got := pickCVSS("redhat", cvss); got != 7.5 {
		t.Errorf("got %v, want the severity source score 7.5", got)
	}
	if got := pickCVSS("ghsa", cvss); got != 9.8 {
		t.Errorf("got %v, want the NVD score when the source has none", got)
	}
	if got := pickCVSS("", map[string]cvssEntry{"a": {V3Score: 5}, "b": {V3Score: 6.1}}); got != 6.1 {
		t.Errorf("got %v, want the highest score as a last resort", got)
	}
}
