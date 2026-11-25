package exception

import (
	"errors"
	"fmt"
	"strings"

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
	return validateImage(name, prefix)
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

func validateImage(name, prefix string) error {
	if strings.Contains(prefix, "@") {
		return fmt.Errorf("artifact %q: drop the digest; an exception applies to every tag and digest of an image", name)
	}
	if model.ImageName(prefix) != prefix {
		return fmt.Errorf("artifact %q: drop the tag; an exception applies to every tag and digest of an image", name)
	}
	return nil
}

// AppliesTo reports whether the exception covers findings in the artifact
// with this name: an image name, or dir:NAME (see model.ScanResult's
// ArtifactName). An exception without artifact applies everywhere.
func (e Exception) AppliesTo(artifact string) bool {
	if len(e.Artifact) == 0 {
		return true
	}
	for _, pattern := range e.Artifact {
		if matchesArtifact(pattern, artifact) {
			return true
		}
	}
	return false
}

// matchesArtifact compares exactly, or by prefix when the pattern ends in
// *. A pattern for images never matches a directory and the other way
// round, whatever the prefix.
func matchesArtifact(pattern, artifact string) bool {
	if artifact == "" || strings.HasPrefix(pattern, directoryPrefix) != strings.HasPrefix(artifact, directoryPrefix) {
		return false
	}
	if prefix, glob := strings.CutSuffix(pattern, "*"); glob {
		return strings.HasPrefix(artifact, prefix)
	}
	return pattern == artifact
}

// Scope describes where the exception applies, for reports: "" when it
// applies everywhere.
func (e Exception) Scope() string {
	if len(e.Artifact) == 0 {
		return ""
	}
	return "only in " + strings.Join(e.Artifact, ", ")
}
