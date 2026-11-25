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
	running := make([]model.ArtifactID, 0, len(images))
	for _, img := range images {
		running = append(running, runningArtifact(img))
	}
	for _, ex := range excs {
		if len(ex.Artifact) == 0 || !ex.Active(env.Now()) || appliesToAny(ex, running) {
			continue
		}
		fmt.Fprintf(env.Stderr, "scanproof: warning: exception %s is limited to %s, which matched no running image or directory\n",
			ex.ID, strings.Join(ex.Artifact, ", "))
	}
}

func runningArtifact(img inventory.RunningImage) model.ArtifactID {
	if img.Directory {
		return model.ArtifactIDOf(model.ArtifactDirectory, img.Reference, nil)
	}
	return model.ArtifactIDOf(model.ArtifactContainerImage, img.Reference, nil)
}

func appliesToAny(ex exception.Exception, artifacts []model.ArtifactID) bool {
	for _, a := range artifacts {
		if ex.AppliesTo(a) {
			return true
		}
	}
	return false
}
