package model

// ArtifactName is the name an artifact is grouped and matched by: an
// image's name without tag or digest, or dir:NAME for a directory, so every
// version of a directory shares one name that never equals an image's.
// Results written before directories were supported have no artifact type
// and are images.
func ArtifactName(artifactType, reference string, dir *Directory) string {
	if artifactType != ArtifactDirectory {
		return ImageName(reference)
	}
	name, _, ok := ParseDirectoryReference(reference)
	if !ok && dir != nil {
		name = dir.Name
	}
	return DirectoryReference(name, "")
}

// ArtifactName is the name the scanned artifact is grouped and matched by.
func (r ScanResult) ArtifactName() string {
	return ArtifactName(r.ArtifactType, r.Image.Reference, r.Directory)
}
