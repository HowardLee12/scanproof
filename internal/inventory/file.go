package inventory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/HowardLee12/scanproof/internal/model"
)

// treeDigestPattern is the form of a directory's tree digest, and of an
// image digest in the images file.
var treeDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// File reads running images and deployed directories from a text file, one
// per line. Use it for hosts that are not in Kubernetes or ECS, and for
// software that is not in an image:
//
//	cr.example.com/vllm:0.9@sha256:<digest>    gpu-cluster/inference/vllm
//	dir:acme-vllm:0.9.1@sha256:<tree digest>   gpu-cluster/inference/vllm
//
// Text after the first run of whitespace is a free-text location. Blank
// lines and lines starting with # are ignored. A line that starts with dir:
// is always a directory. Every malformed line, image or directory, is
// reported as a failure that names the line; the other lines are still
// read.
type File struct {
	Path string
}

// List reads the file. Lines it cannot read are returned in a
// *PartialError, together with every line it could read.
func (f File) List(_ context.Context) ([]RunningImage, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, fmt.Errorf("open image list: %w", err)
	}
	defer fh.Close()
	out := make([]RunningImage, 0)
	failures := make([]Failure, 0)
	sc := bufio.NewScanner(fh)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		img, err := parseLine(line, "listed in "+f.Path)
		if err != nil {
			failures = append(failures, Failure{Where: fmt.Sprintf("images file %s line %d", f.Path, n), Err: err})
			continue
		}
		out = append(out, img)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read image list: %w", err)
	}
	if len(failures) > 0 {
		return out, &PartialError{Failures: failures}
	}
	return out, nil
}

// parseLine reads "SPEC [LOCATION]". defaultLocation is used when the line
// names none.
func parseLine(line, defaultLocation string) (RunningImage, error) {
	spec, location := line, defaultLocation
	if i := strings.IndexFunc(line, unicode.IsSpace); i >= 0 {
		spec, location = line[:i], strings.TrimSpace(line[i:])
	}
	if strings.HasPrefix(spec, "dir:") {
		return parseDirectory(spec, location)
	}
	return parseImage(spec, location)
}

// parseImage reads an image reference, optionally pinned with
// @sha256:<digest>. The reference must parse, and a digest must be complete.
func parseImage(spec, location string) (RunningImage, error) {
	ref, digest, pinned := strings.Cut(spec, "@")
	if strings.HasPrefix(spec, "-") {
		return RunningImage{}, fmt.Errorf("%q is not an image reference", spec)
	}
	if pinned && !treeDigestPattern.MatchString(digest) {
		return RunningImage{}, fmt.Errorf("%q is not a full image digest (sha256: and 64 lowercase hex characters)", digest)
	}
	if _, err := name.ParseReference(spec); err != nil {
		return RunningImage{}, fmt.Errorf("%q is not an image reference: %v", spec, referenceProblem(spec, pinned))
	}
	return RunningImage{Reference: ref, Digest: digest, Locations: []string{location}}, nil
}

// referenceProblem says why a reference does not parse. ParseReference only
// says that it does not; NewDigest and NewTag say why.
func referenceProblem(spec string, pinned bool) error {
	var err error
	if pinned {
		_, err = name.NewDigest(spec)
	} else {
		_, err = name.NewTag(spec)
	}
	if err == nil {
		return errors.New("it does not parse")
	}
	return err
}

// parseDirectory reads dir:NAME[:VERSION]@sha256:<tree digest>.
func parseDirectory(spec, location string) (RunningImage, error) {
	ref, digest, ok := strings.Cut(spec, "@")
	if !ok {
		return RunningImage{}, errors.New("a directory needs @sha256:<tree digest> (dir:NAME[:VERSION]@sha256:...)")
	}
	if !treeDigestPattern.MatchString(digest) {
		return RunningImage{}, fmt.Errorf("%q is not a tree digest (sha256: and 64 lowercase hex characters)", digest)
	}
	if _, _, ok := model.ParseDirectoryReference(ref); !ok {
		return RunningImage{}, fmt.Errorf("invalid directory %q: use dir:NAME or dir:NAME:VERSION with letters, digits, "+
			"'.', '_', '-' ('/' between parts of the name, '+' in the version)", ref)
	}
	return RunningImage{Reference: ref, Digest: digest, Locations: []string{location}, Directory: true}, nil
}
