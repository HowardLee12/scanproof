package model

// ArtifactID is what an artifact is matched by: an image's name without tag
// or digest, or a directory's NAME. The kind comes from the scan, never from
// the name, so an image from a registry host named "dir" stays an image.
type ArtifactID struct {
	Directory bool
	Name      string
}

// String is the name findings are grouped by: the image name, or dir:NAME
// for a directory, so every version of a directory shares one name.
func (a ArtifactID) String() string {
	if a.Directory {
		return DirectoryReference(a.Name, "")
	}
	return a.Name
}

// ArtifactIDOf identifies an artifact from its type, reference and, for a
// directory, its description. Results written before directories were
// supported have no artifact type and are images.
func ArtifactIDOf(artifactType, reference string, dir *Directory) ArtifactID {
	if artifactType != ArtifactDirectory {
		return ArtifactID{Name: ImageName(reference)}
	}
	name, _, ok := ParseDirectoryReference(reference)
	if !ok && dir != nil {
		name = dir.Name
	}
	return ArtifactID{Directory: true, Name: name}
}

// ArtifactName is the name an artifact is grouped by (see ArtifactID.String).
func ArtifactName(artifactType, reference string, dir *Directory) string {
	return ArtifactIDOf(artifactType, reference, dir).String()
}

// ArtifactID identifies the scanned artifact.
func (r ScanResult) ArtifactID() ArtifactID {
	return ArtifactIDOf(r.ArtifactType, r.Image.Reference, r.Directory)
}

// ArtifactName is the name the scanned artifact is grouped by.
func (r ScanResult) ArtifactName() string {
	return r.ArtifactID().String()
}
