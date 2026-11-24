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

	"github.com/HowardLee12/scanproof/internal/model"
)

// treeDigestPattern is the form of a directory's tree digest.
var treeDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// File reads running images and deployed directories from a text file, one
// per line. Use it for hosts that are not in Kubernetes or ECS, and for
// software that is not in an image:
//
//	cr.example.com/vllm:0.9@sha256:<digest>    gpu-cluster/inference/vllm
//	dir:acme-vllm:0.9.1@sha256:<tree digest>   gpu-cluster/inference/vllm
//
// Text after the first run of whitespace is a free-text location. Blank
// lines and lines starting with # are ignored. A malformed directory line
// is an error that names the line.
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
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		img, err := parseLine(line, "listed in "+f.Path)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", f.Path, n, err)
		}
		out = append(out, img)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read image list: %w", err)
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
	ref, _, _ := strings.Cut(spec, "@")
	return RunningImage{Reference: ref, Digest: model.DigestOf(spec), Locations: []string{location}}, nil
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
			"'.', '_', '-' (and '/' in the name, '+' in the version)", ref)
	}
	return RunningImage{Reference: ref, Digest: digest, Locations: []string{location}, Directory: true}, nil
}
