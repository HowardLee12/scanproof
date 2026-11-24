package model

import "testing"

func TestImageName(t *testing.T) {
	cases := map[string]string{
		"repo/api:1":                     "repo/api",
		"registry:5000/team/api:2.0":     "registry:5000/team/api",
		"ghcr.io/org/app@sha256:abc":     "ghcr.io/org/app",
		"ghcr.io/org/app:1.0@sha256:abc": "ghcr.io/org/app",
		"alpine":                         "alpine",
	}
	for in, want := range cases {
		if got := ImageName(in); got != want {
			t.Errorf("ImageName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDigestOf(t *testing.T) {
	if got := DigestOf("repo/app:1@sha256:abc"); got != "sha256:abc" {
		t.Errorf("got %q", got)
	}
	if got := DigestOf("repo/app:1"); got != "" {
		t.Errorf("got %q", got)
	}
}
