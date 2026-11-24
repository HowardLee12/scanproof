package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/cicontext"
	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

func sampleDoc() report.Document {
	return report.Document{
		ReportID: "SR-20261124-7F3A9C",
		Verdict:  policy.VerdictWarn,
		Image:    model.Image{Reference: "example/api:1.0 @everyone"},
		Context:  cicontext.Context{Provider: "GitHub Actions", Repository: "org/api", Branch: "main", RunURL: "https://github.com/org/api/actions/runs/1"},
		Policy:   report.PolicyInfo{Mode: policy.ModeWarn},
		Summary: report.Summary{
			Violations: 2,
			Vulnerabilities: []report.SeverityCount{
				{Severity: model.SeverityCritical, Total: 3, Fixable: 3},
				{Severity: model.SeverityHigh, Total: 6, Fixable: 6},
			},
		},
		Vulnerabilities: []policy.VulnerabilityFinding{
			{Vulnerability: model.Vulnerability{ID: "CVE-2022-48174", Package: "busybox<x>", Severity: model.SeverityCritical, FixedVersion: "1.36.1-r1"}, Violation: true},
			{Vulnerability: model.Vulnerability{ID: "CVE-2023-5363", Package: "libssl3", Severity: model.SeverityHigh, FixedVersion: "3.1.4-r0"}},
		},
	}
}

func TestNewMessage(t *testing.T) {
	m := NewMessage(sampleDoc())
	if m.Title != "ScanProof WARN: example/api:1.0 @everyone" {
		t.Errorf("title = %q", m.Title)
	}
	if !strings.Contains(m.Summary, "2 policy violations") || !strings.Contains(m.Summary, "warn mode") {
		t.Errorf("summary = %q", m.Summary)
	}
	if len(m.Violations) != 1 || m.Violations[0] != "CRITICAL CVE-2022-48174 in busybox<x> (fixed in 1.36.1-r1)" {
		t.Errorf("violations = %v", m.Violations)
	}
	if m.URL != "https://github.com/org/api/actions/runs/1" {
		t.Errorf("url = %q", m.URL)
	}
}

func TestDiscordPayloadBlocksMentions(t *testing.T) {
	raw, err := DiscordPayload(NewMessage(sampleDoc()))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	mentions := p["allowed_mentions"].(map[string]any)["parse"].([]any)
	if len(mentions) != 0 {
		t.Error("mentions such as @everyone in image names must never ping anyone")
	}
	embed := p["embeds"].([]any)[0].(map[string]any)
	if embed["color"].(float64) != float64(colorWarn) || embed["url"] != "https://github.com/org/api/actions/runs/1" {
		t.Errorf("unexpected embed %v", embed)
	}
	if !strings.Contains(embed["description"].(string), "CVE-2022-48174") {
		t.Error("violations should be listed")
	}
}

func TestSlackPayloadEscapesText(t *testing.T) {
	raw, err := SlackPayload(NewMessage(sampleDoc()))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "busybox<x>") || !strings.Contains(text, "busybox&lt;x&gt;") {
		t.Errorf("slack text must escape <, > and &: %s", text)
	}
	if !strings.Contains(text, "<https://github.com/org/api/actions/runs/1|CI run>") {
		t.Errorf("run link missing: %s", text)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Errorf("got %q", got)
	}
	if got := truncate("abc", 4); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestShouldNotify(t *testing.T) {
	cases := []struct {
		when    When
		verdict policy.Verdict
		want    bool
	}{
		{WhenViolation, policy.VerdictPass, false},
		{WhenViolation, policy.VerdictWarn, true},
		{WhenViolation, policy.VerdictFail, true},
		{WhenAlways, policy.VerdictPass, true},
		{WhenNever, policy.VerdictFail, false},
	}
	for _, c := range cases {
		if got := ShouldNotify(c.when, c.verdict); got != c.want {
			t.Errorf("ShouldNotify(%s, %s) = %v", c.when, c.verdict, got)
		}
	}
}

func TestParseWhen(t *testing.T) {
	if w, err := ParseWhen("Always"); err != nil || w != WhenAlways {
		t.Errorf("got %v, %v", w, err)
	}
	if _, err := ParseWhen("sometimes"); err == nil {
		t.Error("expected an error")
	}
}

func TestTargetsFromEnv(t *testing.T) {
	env := map[string]string{
		"SCANPROOF_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/abc",
		"SCANPROOF_SLACK_WEBHOOK_URL":   "",
	}
	targets := TargetsFromEnv(func(k string) string { return env[k] })
	if len(targets) != 1 || targets[0].Name != "Discord" {
		t.Fatalf("targets = %+v", targets)
	}
}

func TestSenderPostsJSONWithUserAgent(t *testing.T) {
	var gotUA, gotType string
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotType = r.Header.Get("User-Agent"), r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := Sender{Client: srv.Client(), UserAgent: "scanproof/test"}
	target := Target{Name: "Discord", URL: srv.URL + "/api/webhooks/1/secret-token", build: DiscordPayload}
	if err := s.Send(context.Background(), target, NewMessage(sampleDoc())); err != nil {
		t.Fatal(err)
	}
	if gotUA != "scanproof/test" || gotType != "application/json" || !json.Valid(body) {
		t.Errorf("ua %q, type %q, body %s", gotUA, gotType, body)
	}
}

func TestSenderErrorNeverIncludesWebhookURL(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := Sender{Client: srv.Client(), UserAgent: "scanproof/test"}
	target := Target{Name: "Slack", URL: srv.URL + "/services/T000/B000/secret-token", build: SlackPayload}
	err := s.Send(context.Background(), target, NewMessage(sampleDoc()))
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected an HTTP 403 error, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("the webhook URL contains a credential and must not appear in errors")
	}
}

func TestSenderRejectsPlainHTTP(t *testing.T) {
	s := Sender{Client: http.DefaultClient}
	target := Target{Name: "Discord", URL: "http://example.com/hook", build: DiscordPayload}
	if err := s.Send(context.Background(), target, NewMessage(sampleDoc())); err == nil {
		t.Fatal("webhooks must use HTTPS")
	}
}

func TestSenderReportsUnreachableHost(t *testing.T) {
	s := Sender{Client: &http.Client{}}
	target := Target{Name: "Discord", URL: "https://127.0.0.1:1/secret-token", build: DiscordPayload}
	err := s.Send(context.Background(), target, NewMessage(sampleDoc()))
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("expected a redacted error, got %v", err)
	}
}

func TestNewMessageForADirectory(t *testing.T) {
	doc := sampleDoc()
	doc.ArtifactType = model.ArtifactDirectory
	doc.Image = model.Image{Reference: "dir:acme-vllm:0.9.1", Digest: "sha256:" + strings.Repeat("ab", 32)}
	doc.Directory = &model.Directory{Name: "acme-vllm", Version: "0.9.1", Path: "/mnt/shared/venvs/vllm", TreeDigest: doc.Image.Digest}
	m := NewMessage(doc)
	if m.Title != "ScanProof WARN: directory acme-vllm:0.9.1" {
		t.Errorf("title = %q", m.Title)
	}
	fields := map[string]string{}
	for _, f := range m.Fields {
		fields[f.Name] = f.Value
	}
	if fields["Path"] != "/mnt/shared/venvs/vllm" || fields["Tree digest"] != "sha256:abababababab…" {
		t.Errorf("fields = %v", fields)
	}
	if _, ok := fields["Tree digest"]; !ok {
		t.Error("the tree digest identifies the directory and must be shown")
	}
	if image := NewMessage(sampleDoc()); len(image.Fields) != 5 {
		t.Errorf("image messages keep their fields: %+v", image.Fields)
	}
}
