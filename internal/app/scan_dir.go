package app

import (
	"context"
	"fmt"

	"github.com/HowardLee12/scanproof/internal/model"
	"github.com/HowardLee12/scanproof/internal/tree"
	"github.com/HowardLee12/scanproof/internal/trivy"
)

// scanDirectory scans software installed in a directory. The tree digest is
// computed before Trivy runs and again afterwards: by the malware scan,
// which hashes exactly the bytes it scans, or by a second digest pass. If
// the two differ the directory changed during the scan, and no evidence is
// written for a mix of two versions.
func scanDirectory(ctx context.Context, opts scanOptions, env Env) (trivy.Scan, error) {
	root, err := tree.ResolveRoot(opts.Dir.Path)
	if err != nil {
		return trivy.Scan{}, err
	}
	if !opts.SBOM {
		fmt.Fprintln(env.Stderr, "scanproof: warning: --sbom=false: rescans cannot check this directory without its stored SBOM")
	}
	before, err := tree.Digest(ctx, root, nil)
	if err != nil {
		return trivy.Scan{}, fmt.Errorf("tree digest of %s: %w", root, err)
	}
	scan, err := trivy.NewRunner(opts.TrivyBin, opts.Timeout).ScanRootfs(ctx, root)
	if err != nil {
		return trivy.Scan{}, err
	}
	malware, after, err := readDirectoryAgain(ctx, opts, env, root)
	if err != nil {
		return trivy.Scan{}, err
	}
	if after != before.Digest {
		return trivy.Scan{}, fmt.Errorf("%s changed while it was being scanned (tree digest %s before, %s after); "+
			"scan it again when nothing is writing to it", root, before.Digest, after)
	}
	return trivy.Scan{Result: directoryResult(scan.Result, opts.Dir, root, before, malware), Raw: scan.Raw}, nil
}

// readDirectoryAgain reads the directory a second time and returns its tree
// digest, with the malware scan when one was asked for.
func readDirectoryAgain(ctx context.Context, opts scanOptions, env Env, root string) (*model.MalwareScan, string, error) {
	if !opts.Malware.Enabled {
		res, err := tree.Digest(ctx, root, nil)
		if err != nil {
			return nil, "", fmt.Errorf("tree digest of %s: %w", root, err)
		}
		return nil, res.Digest, nil
	}
	if opts.Malware.Update {
		updateSignatures(ctx, opts.Malware, env)
	}
	m, err := malwareScanner(opts).ScanDir(ctx, root)
	if err != nil {
		return nil, "", err
	}
	return m, m.TreeDigest, nil
}

// directoryResult describes the scan as a directory: its reference is
// dir:NAME[:VERSION] and its digest is the tree digest, so the evidence store
// indexes it like an image and rescans find its SBOM by tree digest.
func directoryResult(res model.ScanResult, d dirOptions, root string, t tree.Result, m *model.MalwareScan) model.ScanResult {
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
			Files: t.Files, Dirs: t.Dirs, Symlinks: t.Symlinks, Bytes: t.Bytes,
		},
		Scanner:         res.Scanner,
		ScannedAt:       res.ScannedAt,
		Vulnerabilities: res.Vulnerabilities,
		Secrets:         res.Secrets,
		Malware:         m,
	}
}
