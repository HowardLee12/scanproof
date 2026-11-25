package model

import "testing"

func TestArtifactName(t *testing.T) {
	cases := []struct {
		res  ScanResult
		want string
	}{
		{ScanResult{Image: Image{Reference: "cr.example.com/mirror/coredns/coredns:v1.11.1@sha256:abc"}}, "cr.example.com/mirror/coredns/coredns"},
		{ScanResult{Image: Image{Reference: "localhost:5000/team/app:1"}}, "localhost:5000/team/app"},
		{ScanResult{Image: Image{Reference: "alpine"}}, "alpine"},
		{ScanResult{ArtifactType: ArtifactDirectory, Image: Image{Reference: "dir:acme-vllm:0.9.1"}}, "dir:acme-vllm"},
		// Without a version, ImageName would take the name for a tag.
		{ScanResult{ArtifactType: ArtifactDirectory, Image: Image{Reference: "dir:acme-vllm"}}, "dir:acme-vllm"},
		{ScanResult{ArtifactType: ArtifactDirectory, Directory: &Directory{Name: "team/tools"}}, "dir:team/tools"},
	}
	for _, c := range cases {
		if got := c.res.ArtifactName(); got != c.want {
			t.Errorf("%q: got %q, want %q", c.res.Image.Reference, got, c.want)
		}
	}
}

func TestArtifactID(t *testing.T) {
	cases := []struct {
		res  ScanResult
		want ArtifactID
	}{
		{ScanResult{Image: Image{Reference: "cr.example.com/team/api:2.0"}}, ArtifactID{Name: "cr.example.com/team/api"}},
		// The kind comes from the scan, not from the name.
		{ScanResult{Image: Image{Reference: "dir:5000/app:1"}}, ArtifactID{Name: "dir:5000/app"}},
		{ScanResult{ArtifactType: ArtifactDirectory, Image: Image{Reference: "dir:acme-vllm:0.9.1"}}, ArtifactID{Directory: true, Name: "acme-vllm"}},
	}
	for _, c := range cases {
		if got := c.res.ArtifactID(); got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.res.Image.Reference, got, c.want)
		}
	}
}
