package trivy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/tree"
)

// The skip rules below are those of Trivy 0.76.2, the version the ScanProof
// image pins, for directory scans, where ScanProof switches Trivy's secret
// allow rules off (see noAllowRulesConfig). A different Trivy version may
// skip other files; the CI image job checks these rules by planting secrets.
var (
	// walkerSkipTop are top-level directories Trivy never reads.
	walkerSkipTop = []string{"dev", "proc", "sys"}
	// secretSkipDirs, secretSkipFiles and secretSkipExts are what the
	// secret scanner does not read. Extensions are case-sensitive.
	secretSkipDirs  = []string{".git", "node_modules"}
	secretSkipFiles = []string{"go.mod", "go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "Gemfile.lock"}
	secretSkipExts  = []string{".jpg", ".png", ".gif", ".doc", ".pdf", ".bin", ".svg", ".socket", ".deb", ".rpm", ".zip", ".gz", ".gzip", ".tar"}
)

// ModelledVersion is the Trivy version whose skip rules and allow rules
// ScanProof models. The image pins this version.
const ModelledVersion = "0.76.2"

// VersionCaveat says, when a scan used another Trivy version than the one
// modelled, that the lists of skipped files may be wrong; "" otherwise.
func VersionCaveat(version string) string {
	if strings.TrimPrefix(version, "v") == ModelledVersion {
		return ""
	}
	used := "an unknown Trivy version"
	if version != "" {
		used = "Trivy " + version
	}
	return fmt.Sprintf("What Trivy skips is modelled for Trivy %s; this scan used %s, which may skip other files.", ModelledVersion, used)
}

const (
	// BinaryHeadBytes is how much of a file the binary check looks at.
	BinaryHeadBytes = 300
	// secretMinBytes: smaller files are not read; no secret rule fits in them.
	secretMinBytes = 10
	// maxCoveragePaths bounds each list in the evidence.
	maxCoveragePaths = 50
)

// IsBinary reports whether Trivy's secret scanner treats a file as binary
// (and skips it), given the first BinaryHeadBytes of the file.
func IsBinary(head []byte) bool {
	for _, b := range head[:min(len(head), BinaryHeadBytes)] {
		if b < 7 || b == 11 || (13 < b && b < 27) || (27 < b && b < 0x20) || b == 0x7f {
			return true
		}
	}
	return false
}

// Coverage works out which files of a directory Trivy did not read: paths
// its walker skips (checked for neither vulnerabilities nor secrets) and
// files its secret scanner skips. binary reports whether a file's first
// bytes make it binary (see IsBinary).
func Coverage(entries []tree.Entry, binary func(path string) bool) model.Coverage {
	notScanned := map[string]model.UncheckedPath{}
	order := []string{}
	secrets := newUnchecked()
	for _, e := range entries {
		if e.Type == tree.Dir {
			continue
		}
		if root, reason, ok := walkerSkip(e.Path); ok {
			p, seen := notScanned[root]
			if !seen {
				order = append(order, root)
			}
			notScanned[root] = model.UncheckedPath{Path: root, Files: p.Files + 1, Reason: reason}
			continue
		}
		if e.Type == tree.File {
			if reason, ok := secretSkip(e, binary); ok {
				secrets = secrets.add(model.UncheckedPath{Path: e.Path, Files: 1, Reason: reason})
			}
		}
	}
	skipped := newUnchecked()
	for _, root := range order {
		skipped = skipped.add(notScanned[root])
	}
	return model.Coverage{ModelledFor: ModelledVersion, NotScanned: skipped.UncheckedPaths, SecretsNotChecked: secrets.UncheckedPaths}
}

// walkerSkip returns the skipped path (a .git directory or file, or a
// top-level dev, proc or sys) that p is in.
func walkerSkip(p string) (string, string, bool) {
	segs := strings.Split(p, "/")
	if slices.Contains(walkerSkipTop, segs[0]) {
		return segs[0], "Trivy skips dev, proc and sys at the top of the directory", true
	}
	if i := slices.Index(segs, ".git"); i >= 0 {
		return strings.Join(segs[:i+1], "/"), "Trivy skips .git", true
	}
	return "", "", false
}

func secretSkip(e tree.Entry, binary func(string) bool) (string, bool) {
	if e.Size < secretMinBytes {
		return "", false
	}
	dir, name := path.Split(e.Path)
	for _, d := range secretSkipDirs {
		if slices.Contains(strings.Split(dir, "/"), d) {
			return "in a " + d + " directory", true
		}
	}
	switch {
	case slices.Contains(secretSkipFiles, name):
		return "lock or module file", true
	case slices.Contains(secretSkipExts, path.Ext(name)):
		return "file type " + path.Ext(name), true
	case binary(e.Path):
		return "binary file", true
	}
	return "", false
}

// unchecked builds an UncheckedPaths with a bounded list.
type unchecked struct{ model.UncheckedPaths }

func newUnchecked() unchecked {
	return unchecked{model.UncheckedPaths{ByReason: map[string]int{}, Paths: []model.UncheckedPath{}}}
}

func (u unchecked) add(p model.UncheckedPath) unchecked {
	u.Files += p.Files
	u.ByReason[p.Reason] += p.Files
	if len(u.Paths) < maxCoveragePaths {
		u.Paths = append(u.Paths, p)
	} else {
		u.Omitted++
	}
	return u
}
