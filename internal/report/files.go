package report

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const fileMode = 0o644

// NewReportID returns an ID such as SR-20261124-7F3A9C. entropy defaults to
// crypto/rand when nil.
func NewReportID(now time.Time, entropy io.Reader) (string, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(entropy, buf); err != nil {
		return "", fmt.Errorf("generate report ID: %w", err)
	}
	return fmt.Sprintf("SR-%s-%s", now.UTC().Format("20060102"), strings.ToUpper(hex.EncodeToString(buf))), nil
}

// WriteJSON writes v as indented JSON with a trailing newline.
func WriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	return WriteFile(path, append(data, '\n'))
}

// WriteFile writes data, creating or replacing the file.
func WriteFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, fileMode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// HashFile returns the hex SHA-256 and size of a file.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ManifestFile is one hashed output file.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Manifest lets anyone check later that the evidence files were not changed.
type Manifest struct {
	Schema      string         `json:"schema"`
	ReportID    string         `json:"report_id"`
	GeneratedAt time.Time      `json:"generated_at"`
	ImageDigest string         `json:"image_digest,omitempty"`
	Files       []ManifestFile `json:"files"`
}

// BuildManifest hashes the named files of a scan report in dir.
func BuildManifest(dir string, doc Document, names []string) (Manifest, error) {
	return BuildManifestFor(dir, doc.ReportID, doc.GeneratedAt, doc.Image.Digest, names)
}

// BuildManifestFor hashes the named files in dir for any report ID.
func BuildManifestFor(dir, reportID string, generatedAt time.Time, imageDigest string, names []string) (Manifest, error) {
	files := make([]ManifestFile, 0, len(names))
	for _, name := range names {
		sum, size, err := HashFile(filepath.Join(dir, name))
		if err != nil {
			return Manifest{}, err
		}
		files = append(files, ManifestFile{Name: name, SHA256: sum, Bytes: size})
	}
	return Manifest{
		Schema:      "scanproof-manifest/v1",
		ReportID:    reportID,
		GeneratedAt: generatedAt,
		ImageDigest: imageDigest,
		Files:       files,
	}, nil
}

// VerifyAgainstManifest checks that data is the file name listed, with the
// same SHA-256, in an encoded manifest. It returns the decoded manifest.
func VerifyAgainstManifest(manifestData []byte, name string, data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	sum := sha256.Sum256(data)
	for _, file := range m.Files {
		if file.Name == name {
			if file.SHA256 != hex.EncodeToString(sum[:]) {
				return Manifest{}, fmt.Errorf("%s does not match the SHA-256 in its manifest", name)
			}
			return m, nil
		}
	}
	return Manifest{}, fmt.Errorf("manifest does not list %s", name)
}
