// Package inventory finds the container images that are running right now,
// and the deployed directories listed in a file, so they can be rescanned
// against today's vulnerability data.
package inventory

import (
	"context"
	"errors"
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

// Failure is an inventory source, or one line of the images file, that
// could not be read. A rescan reports it as failed and rescans the rest.
type Failure struct {
	Where string
	Err   error
}

// PartialError is returned by a source that listed some images but could
// not read everything; the images it returned are still valid.
type PartialError struct {
	Failures []Failure
}

func (e *PartialError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, f.Where+": "+f.Err.Error())
	}
	return strings.Join(parts, "; ")
}

// NamedSource is a source and the name failures are reported under.
type NamedSource struct {
	Name   string
	Source Source
}

// Combined lists the images of several sources, in order.
type Combined []NamedSource

// List calls every source. A source that fails, and every line a source
// could not read, becomes a Failure; the others are still listed.
func (c Combined) List(ctx context.Context) ([]RunningImage, []Failure) {
	out := make([]RunningImage, 0)
	failures := make([]Failure, 0)
	for _, s := range c {
		images, err := s.Source.List(ctx)
		var partial *PartialError
		switch {
		case errors.As(err, &partial):
			failures = append(failures, partial.Failures...)
		case err != nil:
			failures = append(failures, Failure{Where: s.Name + " inventory", Err: err})
		}
		out = append(out, images...)
	}
	return out, failures
}

// Merge combines copies of one image (the same digest, or the same reference
// when no digest is known) and of one directory (the same reference and tree
// digest), keeping the order in which they were first seen. An image and a
// directory are never merged, even with the same digest.
func Merge(images []RunningImage) []RunningImage {
	out := make([]RunningImage, 0, len(images))
	index := map[string]int{}
	for _, img := range images {
		key := mergeKey(img)
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

func mergeKey(img RunningImage) string {
	if img.Directory {
		return "directory\x00" + img.Reference + "\x00" + img.Digest
	}
	if img.Digest != "" {
		return "image\x00" + img.Digest
	}
	return "image\x00" + img.Reference
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
