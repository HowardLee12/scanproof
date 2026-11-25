package app

import (
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/exception"
	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/model"
)

// warnUnmatchedScopes names every active exception limited to artifacts of
// which none is running. Exceptions for other artifacts are left out of
// each report, so a typo in a name, or an exception that outlived its
// image, would otherwise show nowhere.
func warnUnmatchedScopes(env Env, excs []exception.Exception, images []inventory.RunningImage) {
	names := make([]string, 0, len(images))
	for _, img := range images {
		names = append(names, runningArtifactName(img))
	}
	for _, ex := range excs {
		if len(ex.Artifact) == 0 || !ex.Active(env.Now()) || appliesToAny(ex, names) {
			continue
		}
		fmt.Fprintf(env.Stderr, "scanproof: warning: exception %s is limited to %s, which matched no running image or directory\n",
			ex.ID, strings.Join(ex.Artifact, ", "))
	}
}

func runningArtifactName(img inventory.RunningImage) string {
	if img.Directory {
		return model.ArtifactName(model.ArtifactDirectory, img.Reference, nil)
	}
	return model.ArtifactName(model.ArtifactContainerImage, img.Reference, nil)
}

func appliesToAny(ex exception.Exception, artifacts []string) bool {
	for _, a := range artifacts {
		if ex.AppliesTo(a) {
			return true
		}
	}
	return false
}
