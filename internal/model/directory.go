package model

import (
	"fmt"
	"regexp"
	"strings"
)

// ArtifactDirectory is the artifact type of a directory scan: software
// installed in a directory (a Python virtualenv, a folder of binaries)
// rather than shipped in a container image.
const ArtifactDirectory = "directory"

// directoryPrefix starts the reference of a directory, as in the rescan
// inventory file: dir:NAME[:VERSION].
const directoryPrefix = "dir:"

var (
	directoryNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	directoryVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

// Directory describes a scanned directory tree.
type Directory struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// TreeDigest identifies the exact content (see docs/directories.md).
	TreeDigest string `json:"tree_digest"`
	// Path is where the directory was scanned. Rescans of the stored SBOM
	// have no path; the scan named in runtime.sbom_from has it.
	Path     string `json:"path,omitempty"`
	Files    int    `json:"files,omitempty"`
	Dirs     int    `json:"dirs,omitempty"`
	Symlinks int    `json:"symlinks,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
}

// Label is NAME or NAME:VERSION, for people.
func (d Directory) Label() string {
	if d.Version == "" {
		return d.Name
	}
	return d.Name + ":" + d.Version
}

// DirectoryReference returns dir:NAME or dir:NAME:VERSION. Directory scans
// use it as their reference, so they never look like an image reference.
func DirectoryReference(name, version string) string {
	return directoryPrefix + Directory{Name: name, Version: version}.Label()
}

// ParseDirectoryReference splits dir:NAME[:VERSION]. ok is false when ref is
// not a valid directory reference.
func ParseDirectoryReference(ref string) (name, version string, ok bool) {
	rest, found := strings.CutPrefix(ref, directoryPrefix)
	if !found {
		return "", "", false
	}
	name, version, _ = strings.Cut(rest, ":")
	if ValidateDirectoryName(name) != nil {
		return "", "", false
	}
	if version != "" && ValidateDirectoryVersion(version) != nil {
		return "", "", false
	}
	return name, version, true
}

// ValidateDirectoryName accepts letters, digits, '.', '_', '-' and '/', up
// to 128 characters, starting with a letter or digit.
func ValidateDirectoryName(name string) error {
	if !directoryNamePattern.MatchString(name) {
		return fmt.Errorf("invalid directory name %q: use letters, digits, '.', '_', '-' and '/', "+
			"start with a letter or digit, at most 128 characters", name)
	}
	return nil
}

// ValidateDirectoryVersion accepts letters, digits, '.', '_', '-' and '+',
// up to 128 characters, starting with a letter or digit.
func ValidateDirectoryVersion(version string) error {
	if !directoryVersionPattern.MatchString(version) {
		return fmt.Errorf("invalid directory version %q: use letters, digits, '.', '_', '-' and '+', "+
			"start with a letter or digit, at most 128 characters", version)
	}
	return nil
}
