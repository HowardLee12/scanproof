package model

// Coverage lists what the vulnerability and secret scan of a directory did
// not read. ScanProof works it out from the directory listing and the skip
// rules of the Trivy version it ships (see docs/directories.md#limits).
type Coverage struct {
	// ModelledFor is the Trivy version whose skip rules the lists follow.
	ModelledFor string `json:"modelled_for"`
	// Caveats say why the lists, or the scan, may not be complete: a
	// different Trivy version, or a parent directory others can change.
	Caveats []string `json:"caveats,omitempty"`
	// NotScanned are paths Trivy skips entirely: they were checked for
	// neither vulnerabilities nor secrets.
	NotScanned UncheckedPaths `json:"not_scanned"`
	// SecretsNotChecked are files Trivy's secret scanner does not read.
	SecretsNotChecked UncheckedPaths `json:"secrets_not_checked"`
}

// UncheckedPaths counts files that were not checked, with a bounded list.
type UncheckedPaths struct {
	Files    int             `json:"files"`
	ByReason map[string]int  `json:"by_reason,omitempty"`
	Paths    []UncheckedPath `json:"paths"`
	// Omitted is the number of paths left out of Paths.
	Omitted int `json:"omitted,omitempty"`
}

// UncheckedPath is one file, or one directory of files, that was not checked.
type UncheckedPath struct {
	Path string `json:"path"`
	// Files is the number of files below a directory (1 for a file).
	Files  int    `json:"files"`
	Reason string `json:"reason"`
}
