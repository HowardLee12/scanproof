package exception

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/model"
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
		`"dir:acme-*"`:           {"dir:acme-*"},
		`"dir:team/*"`:           {"dir:team/*"},
		`"dir:*"`:                {"dir:*"},
		`"localhost:5000/*"`:     {"localhost:5000/*"},
		`"cr.example.com:443/*"`: {"cr.example.com:443/*"},
		`"[::1]:5000/team/*"`:    {"[::1]:5000/team/*"},
		`"alpine*"`:              {"alpine*"},
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
		"":                                 "exception EX-1: artifact has no value; leave it out to apply the exception to every image and directory",
		"null":                             "artifact has no value",
		"~":                                "artifact has no value",
		"[example-api, ~]":                 "a name cannot be empty",
		"[null]":                           "a name cannot be empty",
		`"cr.example.com/app/"`:            `artifact "cr.example.com/app/": a name cannot have an empty part between slashes`,
		`"/app"`:                           "a name cannot have an empty part between slashes",
		`"cr.example.com//app"`:            "a name cannot have an empty part between slashes",
		`"cr.example.com//*"`:              "a name cannot have an empty part between slashes",
		`"Cr.Example.com/App"`:             `artifact "Cr.Example.com/App": use lower case`,
		`"cr.example.com/app~x"`:           `artifact "cr.example.com/app~x": not an image name: repository can only contain`,
		`"cr.example.com/app~*"`:           "not an image name",
		`"localhost:5000*"`:                `artifact "localhost:5000*": put / after a registry port, as in localhost:5000/*`,
		"[[example-api]]":                  "artifact must be a name or a list of names",
		// A * right after a registry would also match other registries.
		`"cr.example.com*"`:     `artifact "cr.example.com*": a * right after a registry would also match other registries; end the registry with /, as in cr.example.com/*`,
		`"docker.io*"`:          "end the registry with /, as in docker.io/*",
		`"localhost*"`:          "end the registry with /, as in localhost/*",
		`"cr.example.com:443*"`: "put / after a registry port, as in cr.example.com:443/*",
		`"CR.EXAMPLE.COM/app"`:  `artifact "CR.EXAMPLE.COM/app": use lower case; image names are compared exactly`,
		`"CR.EXAMPLE.COM/*"`:    "use lower case",
	}
	for in, want := range cases {
		_, err := Parse([]byte(oneException(in)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", in, err, want)
		}
	}
}

func image(name string) model.ArtifactID { return model.ArtifactID{Name: name} }
func dir(name string) model.ArtifactID   { return model.ArtifactID{Directory: true, Name: name} }

func TestAppliesTo(t *testing.T) {
	cases := []struct {
		scope    Artifacts
		artifact model.ArtifactID
		want     bool
	}{
		{nil, image("example-api"), true},
		{nil, dir("acme-vllm"), true},
		{nil, image(""), true},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, image("cr.example.com/mirror/coredns/coredns"), true},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, image("cr.example.com/mirror/coredns/coredns-extra"), false},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, image("example-api"), false},
		{Artifacts{"cr.example.com/mirror/coredns/coredns"}, image(""), false},
		{Artifacts{"example-api", "dir:acme-vllm"}, dir("acme-vllm"), true},
		{Artifacts{"example-api", "dir:acme-vllm"}, image("example-api"), true},
		{Artifacts{"example-api", "dir:acme-vllm"}, image("acme-vllm"), false},
		{Artifacts{"dir:acme-vllm"}, dir("acme-vllm2"), false},
		{Artifacts{"cr.example.com/mirror/*"}, image("cr.example.com/mirror/coredns/coredns"), true},
		{Artifacts{"cr.example.com/mirror/*"}, image("cr.example.com/mirrors/coredns"), false},
		{Artifacts{"cr.example.com/mirror/*"}, image("cr.example.com/mirror"), false},
		{Artifacts{"dir:acme-*"}, dir("acme-vllm"), true},
		{Artifacts{"dir:acme-*"}, image("acme-vllm"), false},
		{Artifacts{"dir:*"}, dir("acme-vllm"), true},
		// An image pattern never matches a directory, whatever its prefix,
		// and the kind comes from the scan, not from the name: an image
		// from a registry host named "dir" is still an image.
		{Artifacts{"d*"}, image("docker.io/team/app"), true},
		{Artifacts{"d*"}, dir("acme-vllm"), false},
		{Artifacts{"dir:*"}, image("dir:5000/app"), false},
		{Artifacts{"dir:5000/app"}, image("dir:5000/app"), false},
	}
	for _, c := range cases {
		ex := Exception{ID: "EX-1", Artifact: c.scope}
		if got := ex.AppliesTo(c.artifact); got != c.want {
			t.Errorf("%q applies to %+v = %v, want %v", c.scope, c.artifact, got, c.want)
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

// An exceptions file must say what it means where it says it: YAML
// anchors, aliases and merge keys can bring in a key or a value from
// elsewhere, and a null artifact decodes as if the key were missing, which
// would widen an exception to every artifact. They are refused anywhere.
func TestParseRefusesYAMLIndirection(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"alias as the artifact key": {`
exceptions:
  - id: SCOPED
    finding: CVE-1
    reason: r
    expires: 2099-01-01
    &k artifact: cr.example.com/team/api
  - id: LOOKS-SCOPED
    finding: CVE-2022-48174
    reason: accepted for cr.example.com/team/api only
    expires: 2099-01-01
    *k :
`, "line 7: YAML anchors (&k) are not supported in an exceptions file; write the value out"},
		"merge key around the whole file": {`
<<:
  exceptions:
    - {id: EX-1, finding: CVE-1, reason: r, expires: 2027-01-01, artifact: }
`, "line 2: merge keys (<<) are not supported in an exceptions file; write the fields out"},
		"merge key in an exception": {`
exceptions:
  - id: EX-1
    finding: CVE-1
    <<: {artifact: ~}
    reason: r
    expires: 2027-01-01
`, "line 5: merge keys (<<) are not supported"},
		"alias to a null value": {`
exceptions:
  - id: EX-1
    finding: CVE-1
    approved_by: &n
    artifact: *n
    reason: r
    expires: 2027-01-01
`, "line 5: YAML anchors (&n) are not supported"},
		"alias in a list": {`
exceptions:
  - id: EX-1
    finding: CVE-1
    artifact: [&a example-api, *a]
    reason: r
    expires: 2027-01-01
`, "YAML anchors (&a) are not supported"},
		"anchor on an exception": {`
exceptions:
  - &base {id: EX-1, finding: CVE-1, reason: r, expires: 2027-01-01}
`, "line 3: YAML anchors (&base) are not supported"},
		"anchor on the list": {`
exceptions: &all
  - {id: EX-1, finding: CVE-1, reason: r, expires: 2027-01-01}
`, "line 2: YAML anchors (&all) are not supported"},
		"quoted merge key": {`
exceptions:
  - {id: EX-1, finding: CVE-1, reason: r, expires: 2027-01-01, "<<": {artifact: ~}}
`, "merge keys (<<) are not supported"},
		"artifact without a value": {`
exceptions:
  - id: EX-1
    finding: CVE-1
    artifact:
    reason: r
    expires: 2027-01-01
`, "exception EX-1: artifact has no value"},
		"artifact tagged null": {`
exceptions:
  - {id: EX-1, finding: CVE-1, artifact: !!null x, reason: r, expires: 2027-01-01}
`, "exception EX-1: artifact has no value"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}
