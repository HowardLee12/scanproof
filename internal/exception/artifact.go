package exception

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	ggcrname "github.com/google/go-containerregistry/pkg/name"
	"gopkg.in/yaml.v3"

	"github.com/HowardLee12/scanproof/internal/model"
)

// directoryPrefix starts the name of a directory: dir:NAME.
const directoryPrefix = "dir:"

// Artifacts limits an exception to some images and directories. Each entry
// is an image name without tag or digest (cr.example.com/team/api), or
// dir:NAME for a directory, and may end in * to match every name that
// starts with what comes before it. Empty means every artifact.
type Artifacts []string

// UnmarshalYAML accepts one name or a list of names.
func (a *Artifacts) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*a = Artifacts{node.Value}
		return nil
	case yaml.SequenceNode:
		names := make(Artifacts, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return shapeError(node)
			}
			if item.Tag == nullTag {
				return fmt.Errorf("line %d: artifact: a name cannot be empty", item.Line)
			}
			names = append(names, item.Value)
		}
		*a = names
		return nil
	}
	return shapeError(node)
}

func shapeError(node *yaml.Node) error {
	return fmt.Errorf("line %d: artifact must be a name or a list of names", node.Line)
}

// validate checks every name. A nil list (no artifact key) is fine; an
// explicit empty list is a mistake, not a way to say "everywhere".
func (a Artifacts) validate() error {
	if a != nil && len(a) == 0 {
		return errors.New("artifact is empty; leave it out to apply the exception to every image and directory")
	}
	for _, name := range a {
		if err := validateArtifact(name); err != nil {
			return err
		}
	}
	return nil
}

func validateArtifact(name string) error {
	prefix, glob := strings.CutSuffix(name, "*")
	switch {
	case strings.TrimSpace(name) == "":
		return errors.New("artifact: a name cannot be empty")
	case strings.ContainsAny(name, " \t\n"):
		return fmt.Errorf("artifact %q: a name cannot contain spaces", name)
	case glob && prefix == "":
		return fmt.Errorf("artifact %q: a bare * would match everything; leave artifact out instead", name)
	case strings.Contains(prefix, "*"):
		return fmt.Errorf("artifact %q: * is only allowed at the end, as a prefix match", name)
	}
	if dir, ok := strings.CutPrefix(prefix, directoryPrefix); ok {
		return validateDirectory(name, dir, glob)
	}
	return validateImage(name, prefix, glob)
}

func validateDirectory(name, dir string, glob bool) error {
	if base, _, hasVersion := strings.Cut(dir, ":"); hasVersion && model.ValidateDirectoryName(base) == nil {
		return fmt.Errorf("artifact %q: drop the version; an exception applies to every version of a directory", name)
	}
	if glob && dir == "" {
		return nil // dir:* is every directory
	}
	if glob {
		dir = strings.TrimSuffix(dir, "/") // dir:team/* is every directory under team/
	}
	if err := model.ValidateDirectoryName(dir); err != nil {
		return fmt.Errorf("artifact %q: %w", name, err)
	}
	return nil
}

// validateImage checks an image name, or the part of a pattern before its
// *, with go-containerregistry's rules for a repository, so a name that
// could never match (upper case, an empty part) is refused.
func validateImage(name, prefix string, glob bool) error {
	if err := imageShape(name, prefix, glob); err != nil {
		return err
	}
	path := prefix
	if glob {
		path = strings.TrimSuffix(prefix, "/")
	}
	if slices.Contains(strings.Split(path, "/"), "") {
		return fmt.Errorf("artifact %q: a name cannot have an empty part between slashes", name)
	}
	if _, err := ggcrname.NewRepository(prefix + pick(glob, "x", "")); err != nil {
		return fmt.Errorf("artifact %q: not an image name: %w", name, err)
	}
	return nil
}

// imageShape refuses a digest, a tag, upper case, and a * that could match
// past the end of a registry name (cr.example.com* also matches
// cr.example.com.evil.io).
func imageShape(name, prefix string, glob bool) error {
	switch {
	case strings.Contains(prefix, "@"):
		return fmt.Errorf("artifact %q: drop the digest; an exception applies to every tag and digest of an image", name)
	case prefix != strings.ToLower(prefix):
		return fmt.Errorf("artifact %q: use lower case; image names are compared exactly", name)
	case glob && registryPort.MatchString(prefix):
		return fmt.Errorf("artifact %q: put / after a registry port, as in %s/*", name, prefix)
	case glob && !strings.Contains(prefix, "/") && looksLikeRegistry(prefix):
		return fmt.Errorf("artifact %q: a * right after a registry would also match other registries; "+
			"end the registry with /, as in %s/*", name, prefix)
	case model.ImageName(prefix) != prefix:
		return fmt.Errorf("artifact %q: drop the tag; an exception applies to every tag and digest of an image", name)
	}
	return nil
}

// looksLikeRegistry is how image references tell a registry host from a
// Docker Hub name: it has a dot or a port, or is localhost.
func looksLikeRegistry(first string) bool {
	return strings.ContainsAny(first, ".:") || first == "localhost"
}

// registryPort matches a registry host and port with nothing after it.
var registryPort = regexp.MustCompile(`^[^/]+:[0-9]+$`)

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// AppliesTo reports whether the exception covers findings in the artifact.
// An exception without artifact applies everywhere.
func (e Exception) AppliesTo(a model.ArtifactID) bool {
	if len(e.Artifact) == 0 {
		return true
	}
	for _, pattern := range e.Artifact {
		if matchesArtifact(pattern, a) {
			return true
		}
	}
	return false
}

// matchesArtifact compares exactly, or by prefix when the pattern ends in
// *. A dir: pattern only matches directories and any other pattern only
// images, whatever the name looks like.
func matchesArtifact(pattern string, a model.ArtifactID) bool {
	target, isDir := strings.CutPrefix(pattern, directoryPrefix)
	if !isDir {
		target = pattern
	}
	if a.Name == "" || isDir != a.Directory {
		return false
	}
	if prefix, glob := strings.CutSuffix(target, "*"); glob {
		return strings.HasPrefix(a.Name, prefix)
	}
	return target == a.Name
}

// Scope describes where the exception applies, for reports: "" when it
// applies everywhere.
func (e Exception) Scope() string {
	if len(e.Artifact) == 0 {
		return ""
	}
	return "only in " + strings.Join(e.Artifact, ", ")
}
