package model

import "time"

// Vulnerability is one known vulnerability in one package of the image.
type Vulnerability struct {
	ID               string   `json:"id"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Severity         Severity `json:"severity"`
	CVSS             float64  `json:"cvss,omitempty"`
	Title            string   `json:"title,omitempty"`
	URL              string   `json:"url,omitempty"`
	Target           string   `json:"target"`
	LayerDiffID      string   `json:"layer_diff_id,omitempty"`
	// ScannerStatus is the scanner's own status, e.g. "fixed" or "will_not_fix".
	ScannerStatus string `json:"scanner_status,omitempty"`
}

// Fixable reports whether an upgraded package version exists.
func (v Vulnerability) Fixable() bool {
	return v.FixedVersion != ""
}

// Secret is a credential-like string found in a file of the image. The matched
// text itself is never stored, so results can be shared without leaking it.
type Secret struct {
	RuleID   string   `json:"rule_id"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Target   string   `json:"target"`
	Line     int      `json:"line"`
}

// Image describes the scanned artifact.
type Image struct {
	Reference string     `json:"reference"`
	Digest    string     `json:"digest,omitempty"`
	ImageID   string     `json:"image_id,omitempty"`
	OS        string     `json:"os,omitempty"`
	SizeBytes int64      `json:"size_bytes,omitempty"`
	Layers    int        `json:"layers,omitempty"`
	Created   *time.Time `json:"created,omitempty"`
}

// Scanner records which engine produced the findings and how fresh its data was.
type Scanner struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	DBUpdatedAt *time.Time `json:"db_updated_at,omitempty"`
	// Imported is true when results came from an existing scanner report, so
	// the scanner's settings (for example whether secret scanning ran) are
	// not known.
	Imported bool `json:"imported,omitempty"`
}

// ArtifactContainerImage is the artifact type of a container image scan.
const ArtifactContainerImage = "container_image"

// MalwareEngine records one malware scanner and its signature data.
type MalwareEngine struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Database     string `json:"database,omitempty"`
	DatabaseDate string `json:"database_date,omitempty"`
}

// MalwareDetection is one file one engine flagged.
type MalwareDetection struct {
	Path      string `json:"path"`
	Engine    string `json:"engine"`
	Signature string `json:"signature"`
}

// SkippedFile is a file the malware scan did not read, and why.
type SkippedFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Reason string `json:"reason"`
}

// MalwareScan is the result of scanning the image's files for malware.
type MalwareScan struct {
	Engines      []MalwareEngine    `json:"engines"`
	FilesScanned int                `json:"files_scanned"`
	BytesScanned int64              `json:"bytes_scanned"`
	Skipped      []SkippedFile      `json:"skipped"`
	Detections   []MalwareDetection `json:"detections"`
}

// ScanResult is everything one scan found, before any policy is applied.
type ScanResult struct {
	ArtifactType    string          `json:"artifact_type,omitempty"`
	Image           Image           `json:"image"`
	Scanner         Scanner         `json:"scanner"`
	ScannedAt       time.Time       `json:"scanned_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Secrets         []Secret        `json:"secrets"`
	// Malware is nil when no malware scan ran.
	Malware *MalwareScan `json:"malware,omitempty"`
}
