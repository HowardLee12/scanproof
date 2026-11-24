package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
		_, err := listFile(t, "# ok\n"+line+"\n")
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "line 2") {
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
		staticSource{images: []RunningImage{{Reference: "repo/api:1"}}},
		staticSource{images: []RunningImage{{Reference: "dir:acme-vllm", Directory: true}}},
	}
	got, err := c.List(context.Background())
	if err != nil || len(got) != 2 || got[0].Reference != "repo/api:1" || !got[1].Directory {
		t.Fatalf("got %+v, %v", got, err)
	}
	boom := errors.New("forbidden")
	if _, err := (Combined{c[0], staticSource{err: boom}}).List(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("an error from any source must stop the listing, got %v", err)
	}
}
