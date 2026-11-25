package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/stopped"
	"github.com/HowardLee12/scanproof/internal/tree"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

// scanDirectory scans software installed in a directory. The directory is
// read before Trivy runs and again afterwards (by the malware scan, when it
// runs, which hashes exactly the bytes it scans). Both reads must find the
// same tree with the same file identities and times, so a change during
// the scan, even one that was reverted, writes no evidence.
func scanDirectory(ctx context.Context, opts scanOptions, env Env) (trivy.Scan, error) {
	root, err := tree.ResolveRoot(opts.Dir.Path)
	if err != nil {
		return trivy.Scan{}, err
	}
	if err := refuseWritesInside(root, opts, env); err != nil {
		return trivy.Scan{}, err
	}
	if !opts.SBOM {
		fmt.Fprintln(env.Stderr, "scanproof: warning: --sbom=false: rescans cannot check this directory without its stored SBOM")
	}
	binary := map[string]bool{}
	before, err := tree.Digest(ctx, root, sniffBinary(binary))
	if err != nil {
		return trivy.Scan{}, stopped.InPhase(fmt.Errorf("tree digest of %s: %w", root, err), "the first read of the directory")
	}
	scan, err := trivy.NewRunner(opts.TrivyBin, opts.Timeout).ScanRootfs(ctx, root)
	if err != nil {
		return trivy.Scan{}, err
	}
	if err := tree.CheckRoot(root, before); err != nil {
		return trivy.Scan{}, fmt.Errorf("%s: %w", root, err)
	}
	malware, after, err := readDirectoryAgain(ctx, opts, env, root)
	if err != nil {
		return trivy.Scan{}, err
	}
	if err := tree.Unchanged(before, after); err != nil {
		return trivy.Scan{}, fmt.Errorf("%s was read before and after Trivy and differed: %w", root, err)
	}
	coverage := trivy.Coverage(before.Entries, func(p string) bool { return binary[p] })
	coverage.Caveats = directoryCaveats(env, root, scan.Result.Scanner.Version)
	return trivy.Scan{Result: directoryResult(scan.Result, opts.Dir, root, before, malware, coverage), Raw: scan.Raw}, nil
}

// directoryCaveats are the reasons the evidence of a directory scan may be
// incomplete. Each is also printed as a warning.
func directoryCaveats(env Env, root, trivyVersion string) []string {
	caveats := ancestorWarnings(ancestorsOf(root), currentUID())
	if c := trivy.VersionCaveat(trivyVersion); c != "" {
		caveats = append(caveats, c)
	}
	for _, c := range caveats {
		fmt.Fprintf(env.Stderr, "scanproof: warning: %s\n", c)
	}
	return caveats
}

// sniffBinary records the files whose first bytes make Trivy's secret
// scanner treat them as binary.
func sniffBinary(binary map[string]bool) tree.ContentFunc {
	return func(e tree.Entry, r io.Reader) error {
		head := make([]byte, trivy.BinaryHeadBytes)
		n, err := io.ReadFull(r, head)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if trivy.IsBinary(head[:n]) {
			binary[e.Path] = true
		}
		return nil
	}
}

// readDirectoryAgain reads the directory a second time, with the malware
// scan when one was asked for.
func readDirectoryAgain(ctx context.Context, opts scanOptions, env Env, root string) (*model.MalwareScan, tree.Result, error) {
	if !opts.Malware.Enabled {
		res, err := tree.Digest(ctx, root, nil)
		if err != nil {
			return nil, tree.Result{}, stopped.InPhase(fmt.Errorf("tree digest of %s: %w", root, err), "the second read of the directory")
		}
		return nil, res, nil
	}
	if opts.Malware.Update {
		if err := updateSignatures(ctx, opts.Malware, env); err != nil {
			return nil, tree.Result{}, err
		}
	}
	return malwareScanner(opts, env).ScanDir(ctx, root)
}

// directoryResult describes the scan as a directory: its reference is
// dir:NAME[:VERSION] and its digest is the tree digest, so the evidence store
// indexes it like an image and rescans find its SBOM by tree digest.
func directoryResult(res model.ScanResult, d dirOptions, root string, t tree.Result, m *model.MalwareScan, c model.Coverage) model.ScanResult {
	return model.ScanResult{
		ArtifactType: model.ArtifactDirectory,
		Image: model.Image{
			Reference: model.DirectoryReference(d.Name, d.Version),
			Digest:    t.Digest,
			OS:        res.Image.OS,
			SizeBytes: t.Bytes,
		},
		Directory: &model.Directory{
			Name: d.Name, Version: d.Version, TreeDigest: t.Digest, Path: root,
			Files: t.Files, Dirs: t.Dirs, Symlinks: t.Symlinks, Bytes: t.Bytes, Coverage: &c,
		},
		Scanner:         res.Scanner,
		ScannedAt:       res.ScannedAt,
		Vulnerabilities: res.Vulnerabilities,
		Secrets:         res.Secrets,
		Malware:         m,
	}
}
