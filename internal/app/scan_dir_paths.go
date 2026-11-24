package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// writtenPath is a place a directory scan writes to.
type writtenPath struct{ what, path string }

// refuseWritesInside stops a scan that would write into the directory it
// reads: its own evidence, Trivy's cache or the malware work files would
// change the directory during the scan and could end up in the evidence.
func refuseWritesInside(root string, opts scanOptions, env Env) error {
	for _, w := range writtenPaths(opts, env) {
		if w.path != "" && inside(root, resolvePath(w.path)) {
			return fmt.Errorf("%s %s is inside the scanned directory %s; choose a place outside it", w.what, w.path, root)
		}
	}
	return nil
}

func writtenPaths(opts scanOptions, env Env) []writtenPath {
	out := []writtenPath{{"--out", opts.OutDir}, {"the temporary directory", os.TempDir()}}
	if dir := env.Getenv("TRIVY_CACHE_DIR"); dir != "" {
		out = append(out, writtenPath{"TRIVY_CACHE_DIR", dir})
	} else {
		out = append(out, writtenPath{"Trivy's cache", defaultTrivyCache(env)})
	}
	if opts.Malware.Enabled && opts.Malware.WorkDir != "" {
		out = append(out, writtenPath{"--malware-workdir", opts.Malware.WorkDir})
	}
	return out
}

// defaultTrivyCache is where Trivy keeps its database without
// TRIVY_CACHE_DIR: the user cache directory, as os.UserCacheDir finds it.
func defaultTrivyCache(env Env) string {
	if dir := env.Getenv("XDG_CACHE_HOME"); dir != "" && runtime.GOOS != "darwin" {
		return filepath.Join(dir, "trivy")
	}
	home := env.Getenv("HOME")
	switch {
	case home == "":
		return ""
	case runtime.GOOS == "darwin":
		return filepath.Join(home, "Library", "Caches", "trivy")
	}
	return filepath.Join(home, ".cache", "trivy")
}

// resolvePath makes p absolute and resolves the symlinks of the part of it
// that exists, so a path that does not exist yet can still be compared.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	rest := ""
	for cur := abs; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// inside reports whether p is root or below it. On macOS and Windows file
// systems usually ignore case, so the comparison does too.
func inside(root, p string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		root, p = strings.ToLower(root), strings.ToLower(p)
	}
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
