package model

import (
	"strings"
	"testing"
)

func TestDirectoryReference(t *testing.T) {
	if got := DirectoryReference("acme-vllm", "0.9.1"); got != "dir:acme-vllm:0.9.1" {
		t.Errorf("got %q", got)
	}
	if got := DirectoryReference("acme-vllm", ""); got != "dir:acme-vllm" {
		t.Errorf("got %q", got)
	}
}

func TestParseDirectoryReference(t *testing.T) {
	cases := []struct {
		ref, name, version string
		ok                 bool
	}{
		{"dir:acme-vllm:0.9.1", "acme-vllm", "0.9.1", true},
		{"dir:acme-vllm", "acme-vllm", "", true},
		{"dir:gpu/worker:2026-11-24+cu124", "gpu/worker", "2026-11-24+cu124", true},
		{"acme-vllm:0.9.1", "", "", false},
		{"dir:", "", "", false},
		{"dir::1", "", "", false},
		{"dir:a:b:c", "", "", false},
		{"dir:a b", "", "", false},
		{"dir:a@sha256:x", "", "", false},
	}
	for _, c := range cases {
		name, version, ok := ParseDirectoryReference(c.ref)
		if ok != c.ok || name != c.name || version != c.version {
			t.Errorf("ParseDirectoryReference(%q) = %q %q %v", c.ref, name, version, ok)
		}
	}
}

func TestValidateDirectoryNameAndVersion(t *testing.T) {
	for _, good := range []string{"acme-vllm", "ocr_worker.v2", "gpu/vllm", "A1"} {
		if err := ValidateDirectoryName(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"", "-flag", "a:b", "a@b", "a b", "a\nb", "/abs", strings.Repeat("a", 129)} {
		if err := ValidateDirectoryName(bad); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
	for _, good := range []string{"0.9.1", "v1.2.3+cu124", "2026-11-24", "latest"} {
		if err := ValidateDirectoryVersion(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"1:2", "1 2", "a/b", "-1", "1@2"} {
		if err := ValidateDirectoryVersion(bad); err == nil {
			t.Errorf("version %q should be rejected", bad)
		}
	}
}

func TestDirectoryLabel(t *testing.T) {
	d := Directory{Name: "acme-vllm", Version: "0.9.1"}
	if got := d.Label(); got != "acme-vllm:0.9.1" {
		t.Errorf("got %q", got)
	}
	if got := (Directory{Name: "acme-vllm"}).Label(); got != "acme-vllm" {
		t.Errorf("got %q", got)
	}
}

func TestDirectoryReferenceEdgeCases(t *testing.T) {
	for _, ref := range []string{"dir:acme:", "dir:a//b", "dir:a/", "dir:a/../b", "dir:a/./b", "dir:../a", "dir:a/.hidden"} {
		if _, _, ok := ParseDirectoryReference(ref); ok {
			t.Errorf("%q must be rejected", ref)
		}
	}
	for _, ref := range []string{"dir:gpu/vllm", "dir:gpu/vllm-2.x:1", "dir:a.b_c-d/e"} {
		if _, _, ok := ParseDirectoryReference(ref); !ok {
			t.Errorf("%q must be accepted", ref)
		}
	}
}
