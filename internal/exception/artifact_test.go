package exception

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func oneException(artifact string) string {
	return "exceptions:\n  - id: EX-1\n    finding: CVE-2023-45853\n    reason: r\n    expires: 2027-01-01\n" +
		"    artifact: " + artifact + "\n"
}

func TestParseArtifactScope(t *testing.T) {
	cases := map[string][]string{
		"cr.example.com/mirror/coredns/coredns":                              {"cr.example.com/mirror/coredns/coredns"},
		"[example-api, dir:acme-vllm]":                                       {"example-api", "dir:acme-vllm"},
		"\n      - cr.example.com/mirror/*\n      - localhost:5000/team/app": {"cr.example.com/mirror/*", "localhost:5000/team/app"},
		`"dir:acme-*"`: {"dir:acme-*"},
		`"dir:team/*"`: {"dir:team/*"},
		`"dir:*"`:      {"dir:*"},
	}
	for in, want := range cases {
		list, err := Parse([]byte(oneException(in)))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if !reflect.DeepEqual([]string(list[0].Artifact), want) {
			t.Errorf("%s: artifact = %q, want %q", in, list[0].Artifact, want)
		}
	}
	list, err := Parse([]byte(validYAML))
	if err != nil || list[0].Artifact != nil {
		t.Fatalf("without artifact an exception applies everywhere: %+v, %v", list, err)
	}
}

func TestParseRejectsBadArtifactScopes(t *testing.T) {
	cases := map[string]string{
		`""`:                               "exception EX-1: artifact: a name cannot be empty",
		"[]":                               "exception EX-1: artifact is empty; leave it out to apply the exception to every image and directory",
		"[example-api, '  ']":              "a name cannot be empty",
		"example-api:1.0":                  `artifact "example-api:1.0": drop the tag; an exception applies to every tag and digest of an image`,
		"example-api@sha256:0123abcd":      `artifact "example-api@sha256:0123abcd": drop the digest`,
		"cr.example.com/app:1@sha256:0123": "drop the digest",
		"dir:acme-vllm:0.9.1":              `artifact "dir:acme-vllm:0.9.1": drop the version; an exception applies to every version of a directory`,
		`"dir:acme vllm"`:                  "a name cannot contain spaces",
		`"dir:../etc"`:                     "invalid directory name",
		`"dir:/*"`:                         "invalid directory name",
		`"dir:"`:                           "invalid directory name",
		`"*"`:                              `artifact "*": a bare * would match everything; leave artifact out instead`,
		`"cr.example.com/*/coredns"`:       `artifact "cr.example.com/*/coredns": * is only allowed at the end, as a prefix match`,
		`"cr.example.com/mirror/app:*"`:    "drop the tag",
		`"example api"`:                    `artifact "example api": a name cannot contain spaces`,
		"{name: example-api}":              "artifact must be a name or a list of names",
		"[[example-api]]":                  "artifact must be a name or a list of names",
	}
	for in, want := range cases {
		_, err := Parse([]byte(oneException(in)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", in, err, want)
		}
	}
}

func TestAppliesTo(t *testing.T) {
	cases := []struct {
		scope    Artifacts
		artifact string
		want     bool
	}{
		{nil, "example-api", true},
		{nil, "dir:acme-vllm", true},
		{nil, "", true},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, "cr.example.com/mirror/coredns/coredns", true},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, "cr.example.com/mirror/coredns/coredns-extra", false},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, "example-api", false},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, "", false},
		{Artifacts{"example-api", "dir:acme-vllm"}, "dir:acme-vllm", true},
		{Artifacts{"example-api", "dir:acme-vllm"}, "example-api", true},
		{Artifacts{"example-api", "dir:acme-vllm"}, "acme-vllm", false},
		{Artifacts{"dir:acme-vllm"}, "dir:acme-vllm2", false},
		{Artifacts{"cr.example.com/mirror/*"}, "cr.example.com/mirror/coredns/coredns", true},
		{Artifacts{"cr.example.com/mirror/*"}, "cr.example.com/mirrors/coredns", false},
		{Artifacts{"cr.example.com/mirror/*"}, "cr.example.com/mirror", false},
		{Artifacts{"dir:acme-*"}, "dir:acme-vllm", true},
		{Artifacts{"dir:acme-*"}, "acme-vllm", false},
		// An image pattern never matches a directory, whatever its prefix.
		{Artifacts{"d*"}, "docker.io/team/app", true},
		{Artifacts{"d*"}, "dir:acme-vllm", false},
	}
	for _, c := range cases {
		ex := Exception{ID: "EX-1", Artifact: c.scope}
		if got := ex.AppliesTo(c.artifact); got != c.want {
			t.Errorf("%q applies to %q = %v, want %v", c.scope, c.artifact, got, c.want)
		}
	}
}

func TestArtifactJSONRoundTrip(t *testing.T) {
	list, err := Parse([]byte(oneException(`[example-api, "dir:acme-vllm"]`)))
	if err != nil {
		t.Fatal(err)
	}
	in := list[0]
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"artifact":["example-api","dir:acme-vllm"]`) {
		t.Errorf("results.json should list the scope: %s", data)
	}
	var out Exception
	if err := json.Unmarshal(data, &out); err != nil || !reflect.DeepEqual(out.Artifact, in.Artifact) {
		t.Fatalf("round trip: %+v, %v", out, err)
	}
	if data, _ := json.Marshal(Exception{ID: "EX-2"}); strings.Contains(string(data), "artifact") {
		t.Errorf("an exception without a scope has no artifact field: %s", data)
	}
}

func TestScopeDescription(t *testing.T) {
	if got := (Exception{}).Scope(); got != "" {
		t.Errorf("global: %q", got)
	}
	ex := Exception{Artifact: Artifacts{"cr.example.com/mirror/*", "dir:acme-vllm"}}
	if got := ex.Scope(); got != "only in cr.example.com/mirror/*, dir:acme-vllm" {
		t.Errorf("scoped: %q", got)
	}
}
