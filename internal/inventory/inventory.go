// Package inventory finds the container images that are running right now,
// and the deployed directories listed in a file, so they can be rescanned
// against today's vulnerability data.
package inventory

import (
	"context"
	"strings"

	"github.com/HowardLee12/scanproof/internal/model"
)

// RunningImage is one image, or one deployed directory, and the places it
// runs. A directory's Reference is dir:NAME[:VERSION] and its Digest is the
// tree digest; it can only be rescanned from a stored SBOM.
type RunningImage struct {
	Reference string   `json:"reference"`
	Digest    string   `json:"digest,omitempty"`
	Locations []string `json:"locations"`
	Directory bool     `json:"directory,omitempty"`
}

// Label names the image or directory for people.
func (r RunningImage) Label() string {
	if r.Directory {
		return "directory " + strings.TrimPrefix(r.Reference, "dir:")
	}
	return r.Reference
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

// Combined lists the images of several sources, in order.
type Combined []Source

// List calls every source; an error from any of them stops the listing.
func (c Combined) List(ctx context.Context) ([]RunningImage, error) {
	out := make([]RunningImage, 0)
	for _, s := range c {
		images, err := s.List(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, images...)
	}
	return out, nil
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
			out = append(out, RunningImage{Reference: img.Reference, Digest: img.Digest, Directory: img.Directory})
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
