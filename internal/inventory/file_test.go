package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const treeA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const treeB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func listFile(t *testing.T, content string) ([]RunningImage, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "images.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return File{Path: path}.List(context.Background())
}

func TestFileListsDirectoriesAndLocations(t *testing.T) {
	got, err := listFile(t, strings.Join([]string{
		"# GPU nodes",
		"dir:acme-vllm:0.9.1@" + treeA + "   gpu-cluster/inference/vllm",
		"dir:example-worker@" + treeB,
		"cr.example.com/vllm:0.9@" + digestA + "\tgpu-cluster/inference/vllm  (sidecar)",
		"repo/web:2",
		"",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %+v", got)
	}
	vllm := got[0]
	if !vllm.Directory || vllm.Reference != "dir:acme-vllm:0.9.1" || vllm.Digest != treeA ||
		strings.Join(vllm.Locations, ",") != "gpu-cluster/inference/vllm" {
		t.Errorf("directory with location = %+v", vllm)
	}
	worker := got[1]
	if !worker.Directory || worker.Reference != "dir:example-worker" || !strings.HasPrefix(worker.Locations[0], "listed in ") {
		t.Errorf("directory without version or location = %+v", worker)
	}
	image := got[2]
	if image.Directory || image.Reference != "cr.example.com/vllm:0.9" || image.Digest != digestA ||
		image.Locations[0] != "gpu-cluster/inference/vllm  (sidecar)" {
		t.Errorf("image with location = %+v", image)
	}
	if got[3].Directory || got[3].Reference != "repo/web:2" || got[3].Digest != "" {
		t.Errorf("plain image line = %+v", got[3])
	}
}

func TestFileRejectsBadDirectoryLines(t *testing.T) {
	cases := map[string]string{
		"dir:acme-vllm:0.9.1":                              "needs @sha256",
		"dir:acme-vllm@sha256:abc":                         "tree digest",
		"dir:acme-vllm@sha512:" + strings.Repeat("a", 128): "tree digest",
		"dir:-bad@" + treeA:                                "invalid directory",
		"dir:a:b:c@" + treeA:                               "invalid directory",
	}
	for line, want := range cases {
		images, err := listFile(t, "# ok\n"+line+"\n")
		if len(images) != 0 || err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%q: got %v, want an error with %q and the line number", line, err, want)
		}
	}
}

func TestMergeKeepsDirectoriesApart(t *testing.T) {
	got := Merge([]RunningImage{
		{Reference: "dir:acme-vllm:0.9.1", Digest: treeA, Directory: true, Locations: []string{"node-a"}},
		{Reference: "dir:acme-vllm:0.9.1", Digest: treeA, Directory: true, Locations: []string{"node-b"}},
		{Reference: "repo/api:1", Digest: digestA, Locations: []string{"k8s prod/api"}},
	})
	if len(got) != 2 || !got[0].Directory || len(got[0].Locations) != 2 || got[1].Directory {
		t.Fatalf("got %+v", got)
	}
}

func TestLabel(t *testing.T) {
	if got := (RunningImage{Reference: "dir:acme-vllm:0.9.1", Directory: true}).Label(); got != "directory acme-vllm:0.9.1" {
		t.Errorf("got %q", got)
	}
	if got := (RunningImage{Reference: "repo/api:1"}).Label(); got != "repo/api:1" {
		t.Errorf("got %q", got)
	}
}

type staticSource struct {
	images []RunningImage
	err    error
}

func (s staticSource) List(context.Context) ([]RunningImage, error) { return s.images, s.err }

func TestCombinedListsEverySourceInOrder(t *testing.T) {
	c := Combined{
		{Name: "kubernetes", Source: staticSource{images: []RunningImage{{Reference: "repo/api:1"}}}},
		{Name: "file", Source: staticSource{images: []RunningImage{{Reference: "dir:acme-vllm", Directory: true}}}},
	}
	got, failures := c.List(context.Background())
	if len(failures) != 0 || len(got) != 2 || got[0].Reference != "repo/api:1" || !got[1].Directory {
		t.Fatalf("got %+v, %v", got, failures)
	}
}

func TestFileKeepsGoodLinesWhenSomeAreBad(t *testing.T) {
	got, err := listFile(t, "\ufeffdir:acme-vllm@"+treeA+"\ndir:broken\nrepo/web:2\ndir:acme:@"+treeB+"\n")
	if len(got) != 2 || got[0].Reference != "dir:acme-vllm" || got[1].Reference != "repo/web:2" {
		t.Fatalf("good lines (a byte order mark on line 1 is ignored) = %+v", got)
	}
	var partial *PartialError
	if !errors.As(err, &partial) || len(partial.Failures) != 2 {
		t.Fatalf("want one failure per bad line, got %v", err)
	}
	if !strings.Contains(partial.Failures[0].Where, "line 2") || !strings.Contains(partial.Failures[1].Where, "line 4") {
		t.Errorf("failures = %+v", partial.Failures)
	}
}

func TestMergeKeysOnTheKindOfArtifact(t *testing.T) {
	got := Merge([]RunningImage{
		{Reference: "dir:acme-vllm:1", Digest: treeA, Directory: true, Locations: []string{"a"}},
		{Reference: "dir:other:1", Digest: treeA, Directory: true, Locations: []string{"b"}},
		{Reference: "repo/api:1", Digest: treeA, Locations: []string{"k8s prod/api"}},
		{Reference: "dir:acme-vllm:1", Digest: treeA, Directory: true, Locations: []string{"c"}},
	})
	if len(got) != 3 || strings.Join(got[0].Locations, ",") != "a,c" || got[2].Directory {
		t.Fatalf("got %+v", got)
	}
}

func TestCombinedGoesOnAfterAFailedSource(t *testing.T) {
	boom := errors.New("pods is forbidden")
	c := Combined{
		{Name: "kubernetes", Source: staticSource{err: boom}},
		{Name: "file", Source: staticSource{images: []RunningImage{{Reference: "dir:acme", Directory: true}}, err: &PartialError{
			Failures: []Failure{{Where: "images file x line 3", Err: errors.New("bad line")}}}}},
	}
	images, failures := c.List(context.Background())
	if len(images) != 1 || len(failures) != 2 {
		t.Fatalf("images %+v failures %+v", images, failures)
	}
	if failures[0].Where != "kubernetes inventory" || !errors.Is(failures[0].Err, boom) || failures[1].Where != "images file x line 3" {
		t.Errorf("failures = %+v", failures)
	}
}

func TestFileReportsMalformedImageLines(t *testing.T) {
	zeros := strings.Repeat("0", 64)
	got, err := listFile(t, strings.Join([]string{
		"cr.example.com/vllm:0.9@sha256:" + zeros + "   gpu/vllm",
		"localhost:5000/team/app:1",
		"cr.example.com/app:1.2@sha256:abc123   prod/app",
		"@@@ junk",
		"-rf  /",
		"DIR:acme@sha256:" + zeros,
		"repo/app@md5:" + zeros[:32],
		"repo/app:1@sha256:" + zeros + "@sha256:" + zeros,
	}, "\n"))
	if len(got) != 2 || got[0].Reference != "cr.example.com/vllm:0.9" || got[1].Reference != "localhost:5000/team/app:1" {
		t.Fatalf("good lines = %+v", got)
	}
	var partial *PartialError
	if !errors.As(err, &partial) || len(partial.Failures) != 6 {
		t.Fatalf("want one failure for each of the 6 malformed lines, got %v", err)
	}
	for i, f := range partial.Failures {
		if want := "line " + strconv.Itoa(i+3); !strings.Contains(f.Where, want) {
			t.Errorf("failure %d is %q, want %s", i, f.Where, want)
		}
	}
}

func TestFileSaysWhyAnImageReferenceIsWrong(t *testing.T) {
	_, err := listFile(t, "ghcr.io/Owner/app:1\napp:\n")
	if err == nil || !strings.Contains(err.Error(), "repository can only contain") || !strings.Contains(err.Error(), "tag name after the colon") {
		t.Fatalf("got %v", err)
	}
}
