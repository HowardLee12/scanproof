package report

import "github.com/HowardLee12/scanproof/internal/model"

// artifactType is "directory" for a directory scan and "container_image"
// for everything else (Trivy reports SBOM rescans as "cyclonedx").
func artifactType(res model.ScanResult) string {
	if res.Directory != nil || res.ArtifactType == model.ArtifactDirectory {
		return model.ArtifactDirectory
	}
	return model.ArtifactContainerImage
}

// IsDirectory reports whether the document is a scan of a directory.
func (d Document) IsDirectory() bool {
	return d.ArtifactType == model.ArtifactDirectory
}

// ArtifactLabel names what was scanned, for people: the image reference, or
// "directory NAME[:VERSION]".
func ArtifactLabel(d Document) string {
	if !d.IsDirectory() {
		return d.Image.Reference
	}
	if label := directoryOf(d).Label(); label != "" {
		return "directory " + label
	}
	return "directory " + d.Image.Reference
}

// directoryOf returns the directory details of a directory scan, or what
// its reference says when the details are missing.
func directoryOf(d Document) model.Directory {
	if d.Directory != nil && d.Directory.Name != "" {
		return *d.Directory
	}
	name, version, _ := model.ParseDirectoryReference(d.Image.Reference)
	return model.Directory{Name: name, Version: version, TreeDigest: d.Image.Digest}
}

// subject is the word used for the scanned artifact in running text.
func subject(d Document) string {
	if d.IsDirectory() {
		return "directory"
	}
	return "image"
}
