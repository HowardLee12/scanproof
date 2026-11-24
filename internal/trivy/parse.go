// Package trivy runs the Trivy scanner and converts its JSON report into the
// scanner-independent model.
package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/model"
)

const supportedSchemaVersion = 2

type report struct {
	SchemaVersion int `json:"SchemaVersion"`
	Trivy         struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	CreatedAt    time.Time `json:"CreatedAt"`
	ArtifactName string    `json:"ArtifactName"`
	ArtifactType string    `json:"ArtifactType"`
	Metadata     metadata  `json:"Metadata"`
	Results      []result  `json:"Results"`
}

type metadata struct {
	Size int64 `json:"Size"`
	OS   *struct {
		Family string `json:"Family"`
		Name   string `json:"Name"`
	} `json:"OS"`
	ImageID     string   `json:"ImageID"`
	DiffIDs     []string `json:"DiffIDs"`
	RepoDigests []string `json:"RepoDigests"`
	ImageConfig struct {
		Created *time.Time `json:"created"`
	} `json:"ImageConfig"`
}

type result struct {
	Target          string          `json:"Target"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
	Secrets         []secret        `json:"Secrets"`
}

type vulnerability struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Status           string               `json:"Status"`
	Severity         string               `json:"Severity"`
	SeveritySource   string               `json:"SeveritySource"`
	Title            string               `json:"Title"`
	PrimaryURL       string               `json:"PrimaryURL"`
	CVSS             map[string]cvssEntry `json:"CVSS"`
	Layer            struct {
		DiffID string `json:"DiffID"`
	} `json:"Layer"`
}

type cvssEntry struct {
	V3Score float64 `json:"V3Score"`
}

// secret deliberately has no field for Trivy's "Match" or "Code" output,
// which contain the surrounding text of the credential.
type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
}

// Parse converts a Trivy JSON report (schema version 2) into a ScanResult.
func Parse(r io.Reader) (model.ScanResult, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return model.ScanResult{}, fmt.Errorf("read trivy report: %w", err)
	}
	if rep.SchemaVersion != supportedSchemaVersion {
		return model.ScanResult{}, fmt.Errorf("unsupported trivy report schema version %d (want %d)",
			rep.SchemaVersion, supportedSchemaVersion)
	}

	return model.ScanResult{
		ArtifactType:    rep.ArtifactType,
		Image:           toImage(rep),
		Scanner:         model.Scanner{Name: "trivy", Version: rep.Trivy.Version},
		ScannedAt:       rep.CreatedAt.UTC(),
		Vulnerabilities: toVulnerabilities(rep.Results),
		Secrets:         toSecrets(rep.Results),
	}, nil
}

func toImage(rep report) model.Image {
	md := rep.Metadata
	img := model.Image{
		Reference: rep.ArtifactName,
		Digest:    digestOf(rep.ArtifactName, md.RepoDigests),
		ImageID:   md.ImageID,
		SizeBytes: md.Size,
		Layers:    len(md.DiffIDs),
		Created:   md.ImageConfig.Created,
	}
	if md.OS != nil {
		img.OS = strings.TrimSpace(md.OS.Family + " " + md.OS.Name)
	}
	return img
}

// digestOf prefers a digest pinned in the reference itself, then the first
// registry digest Trivy reported.
func digestOf(reference string, repoDigests []string) string {
	if _, digest, ok := strings.Cut(reference, "@"); ok {
		return digest
	}
	for _, rd := range repoDigests {
		if _, digest, ok := strings.Cut(rd, "@"); ok {
			return digest
		}
	}
	return ""
}

func toVulnerabilities(results []result) []model.Vulnerability {
	out := make([]model.Vulnerability, 0)
	for _, res := range results {
		for _, v := range res.Vulnerabilities {
			out = append(out, model.Vulnerability{
				ID:               v.VulnerabilityID,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         severityOrUnknown(v.Severity),
				CVSS:             pickCVSS(v.SeveritySource, v.CVSS),
				Title:            v.Title,
				URL:              v.PrimaryURL,
				Target:           res.Target,
				LayerDiffID:      v.Layer.DiffID,
				ScannerStatus:    v.Status,
			})
		}
	}
	return out
}

func toSecrets(results []result) []model.Secret {
	out := make([]model.Secret, 0)
	for _, res := range results {
		for _, s := range res.Secrets {
			out = append(out, model.Secret{
				RuleID:   s.RuleID,
				Category: s.Category,
				Severity: severityOrUnknown(s.Severity),
				Title:    s.Title,
				Target:   res.Target,
				Line:     s.StartLine,
			})
		}
	}
	return out
}

func severityOrUnknown(s string) model.Severity {
	sev, err := model.ParseSeverity(s)
	if err != nil {
		return model.SeverityUnknown
	}
	return sev
}

// pickCVSS uses the score from the source that set the severity, then NVD,
// then the highest score any vendor published.
func pickCVSS(source string, scores map[string]cvssEntry) float64 {
	if s, ok := scores[source]; ok && s.V3Score > 0 {
		return s.V3Score
	}
	if s, ok := scores["nvd"]; ok && s.V3Score > 0 {
		return s.V3Score
	}
	highest := 0.0
	for _, s := range scores {
		if s.V3Score > highest {
			highest = s.V3Score
		}
	}
	return highest
}

// VersionInfo is the output of `trivy version --format json`.
type VersionInfo struct {
	Version     string
	DBUpdatedAt *time.Time
}

// ParseVersion reads the output of `trivy version --format json`.
func ParseVersion(r io.Reader) (VersionInfo, error) {
	var raw struct {
		Version         string `json:"Version"`
		VulnerabilityDB *struct {
			UpdatedAt time.Time `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return VersionInfo{}, fmt.Errorf("read trivy version: %w", err)
	}
	info := VersionInfo{Version: raw.Version}
	if raw.VulnerabilityDB != nil && !raw.VulnerabilityDB.UpdatedAt.IsZero() {
		updated := raw.VulnerabilityDB.UpdatedAt.UTC()
		info.DBUpdatedAt = &updated
	}
	return info, nil
}
