package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/HowardLee12/scanproof/internal/model"
)

func TestDefaultPolicyWarnsOnFixableCriticalAndSecrets(t *testing.T) {
	p := Default()
	if p.Mode != ModeWarn || p.MinSeverity != model.SeverityCritical || !p.FixableOnly || !p.BlockSecrets {
		t.Fatalf("unexpected default %+v", p)
	}
}

func TestParseOverridesOnlyGivenFields(t *testing.T) {
	p, err := Parse([]byte("mode: enforce\nfail_on:\n  severity: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeEnforce || p.MinSeverity != model.SeverityHigh {
		t.Errorf("overrides not applied: %+v", p)
	}
	if !p.FixableOnly || !p.BlockSecrets {
		t.Errorf("fields that were not given must keep their defaults: %+v", p)
	}
}

func TestParseCanTurnOffFlags(t *testing.T) {
	p, err := Parse([]byte("fail_on:\n  fixable_only: false\n  secrets: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.FixableOnly || p.BlockSecrets {
		t.Errorf("flags should be off: %+v", p)
	}
}

func TestParseEmptyDocumentGivesDefault(t *testing.T) {
	p, err := Parse(nil)
	if err != nil || p != Default() {
		t.Fatalf("got %+v, %v", p, err)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"mode":          "mode: block\n",
		"severity":      "fail_on:\n  severity: severe\n",
		"unknown field": "fail_on:\n  severities: [HIGH]\n",
		"not yaml":      "mode: [",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseMode(t *testing.T) {
	if m, err := ParseMode("Enforce"); err != nil || m != ModeEnforce {
		t.Errorf("got %v, %v", m, err)
	}
	if _, err := ParseMode("strict"); err == nil {
		t.Error("expected an error")
	}
}

func TestWithModeReturnsCopy(t *testing.T) {
	p := Default()
	q := p.WithMode(ModeEnforce)
	if p.Mode != ModeWarn || q.Mode != ModeEnforce {
		t.Fatalf("WithMode must not change the original: %v %v", p.Mode, q.Mode)
	}
}

func TestLoadRecordsSourceAndHash(t *testing.T) {
	content := []byte("mode: enforce\n")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	p, src, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if p.Mode != ModeEnforce || src.Path != path || src.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected result %+v %+v", p, src)
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestBuiltinSource(t *testing.T) {
	if src := BuiltinSource(); src.Path != "" || src.SHA256 != "" || src.Label() != "built-in default" {
		t.Fatalf("unexpected %+v", src)
	}
	if (Source{Path: "a.yaml"}).Label() != "a.yaml" {
		t.Fatal("a file source is labelled with its path")
	}
}

func TestExamplePolicyIsValid(t *testing.T) {
	if _, _, err := Load("../../examples/policy.yaml"); err != nil {
		t.Fatal(err)
	}
}
