// Package inventory finds the container images that are running right now,
// so they can be rescanned against today's vulnerability data.
package inventory

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/HowardLee12/scanproof/internal/model"
)

// RunningImage is one image and the places it runs.
type RunningImage struct {
	Reference string   `json:"reference"`
	Digest    string   `json:"digest,omitempty"`
	Locations []string `json:"locations"`
}

// ScanReference pins the image by digest when one is known, so the scan
// checks exactly what is running even if the tag has moved.
func (r RunningImage) ScanReference() string {
	if r.Digest == "" {
		return r.Reference
	}
	return model.ImageName(r.Reference) + "@" + r.Digest
}

// Source lists running images.
type Source interface {
	List(ctx context.Context) ([]RunningImage, error)
}

// Merge combines images with the same digest (or the same reference when no
// digest is known), keeping the order in which they were first seen.
func Merge(images []RunningImage) []RunningImage {
	out := make([]RunningImage, 0, len(images))
	index := map[string]int{}
	for _, img := range images {
		key := img.Digest
		if key == "" {
			key = img.Reference
		}
		i, seen := index[key]
		if !seen {
			index[key] = len(out)
			out = append(out, RunningImage{Reference: img.Reference, Digest: img.Digest})
			i = len(out) - 1
		}
		for _, loc := range img.Locations {
			if !contains(out[i].Locations, loc) {
				out[i].Locations = append(out[i].Locations, loc)
			}
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// File reads image references from a text file, one per line. Blank lines
// and lines starting with # are ignored. Use it for hosts that are not in
// Kubernetes or ECS.
type File struct {
	Path string
}

// List reads the file.
func (f File) List(_ context.Context) ([]RunningImage, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, fmt.Errorf("open image list: %w", err)
	}
	defer fh.Close()
	out := make([]RunningImage, 0)
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ref, _, _ := strings.Cut(line, "@")
		out = append(out, RunningImage{Reference: ref, Digest: model.DigestOf(line), Locations: []string{"listed in " + f.Path}})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read image list: %w", err)
	}
	return out, nil
}
