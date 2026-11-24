package report

import (
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/model"
)

func subtitle(doc Document) string {
	if doc.IsDirectory() {
		return "Vulnerability and secret scan of software installed in a directory"
	}
	return "Vulnerability and secret scan run before deployment"
}

func contextTitle(doc Document) string {
	switch {
	case doc.Runtime != nil && doc.IsDirectory():
		return "Deployed directory"
	case doc.Runtime != nil:
		return "Running image"
	}
	return "Change being released"
}

// artifactRows describe what was scanned: an image or a directory.
func artifactRows(doc Document) []pdfRow {
	if doc.IsDirectory() {
		return directoryRows(doc)
	}
	return imageRows(doc.Image)
}

func imageRows(img model.Image) []pdfRow {
	parts := []string{}
	if b := formatBytes(img.SizeBytes); b != "" {
		parts = append(parts, b)
	}
	if img.Layers > 0 {
		parts = append(parts, plural(img.Layers, "layer", "layers"))
	}
	size := strings.Join(parts, " · ")
	return nonEmpty([]pdfRow{
		{Label: "Reference", Value: img.Reference},
		{Label: "Digest", Value: img.Digest, Mono: true},
		{Label: "Operating system", Value: img.OS},
		{Label: "Size", Value: size},
		{Label: "Built", Value: formatTimePtr(img.Created)},
		{Label: "Image ID", Value: img.ImageID, Mono: true},
	})
}

// directoryRows show the name, version, tree digest and, for a scan of the
// directory itself, where it was scanned and what it holds.
func directoryRows(doc Document) []pdfRow {
	d := directoryOf(doc)
	return nonEmpty([]pdfRow{
		{Label: "Name", Value: d.Name},
		{Label: "Version", Value: d.Version},
		{Label: "Tree digest", Value: orText(doc.Image.Digest, d.TreeDigest), Mono: true},
		{Label: "Scanned path", Value: d.Path, Mono: true},
		{Label: "Contents", Value: directoryContents(d)},
		{Label: "Not checked", Value: notCheckedSummary(coverageOf(doc))},
		{Label: "Operating system", Value: doc.Image.OS},
	})
}

func directoryContents(d model.Directory) string {
	if d.Files+d.Dirs+d.Symlinks == 0 && d.Bytes == 0 {
		return ""
	}
	parts := []string{
		plural(d.Files, "file", "files"),
		plural(d.Dirs, "directory", "directories"),
		plural(d.Symlinks, "symlink", "symlinks"),
	}
	if b := formatBytes(d.Bytes); b != "" {
		parts = append(parts, b)
	}
	return strings.Join(parts, " · ")
}

func secretsNote(doc Document) string {
	switch {
	case doc.Runtime != nil && doc.Runtime.Method == MethodSBOM:
		return fmt.Sprintf("This rescan checked the stored SBOM for new vulnerabilities. Secrets were checked when the %s was first scanned.", subject(doc))
	case doc.Scanner.Imported:
		return "These results were imported from an existing Trivy report, so ScanProof could not confirm that secret scanning was enabled."
	}
	return ""
}

func runtimeRows(doc Document) []pdfRow {
	rt := doc.Runtime
	locations := rt.Locations
	more := ""
	if len(locations) > 5 {
		more = fmt.Sprintf(" and %d more", len(locations)-5)
		locations = locations[:5]
	}
	method := "Pulled and scanned the running image"
	if rt.Method == MethodSBOM {
		method = "Checked the SBOM saved by report " + rt.SBOMFrom + " against the current vulnerability database"
	}
	trigger := "Rescan of a running image"
	if doc.IsDirectory() {
		trigger = "Rescan of a deployed directory"
	}
	return []pdfRow{
		{Label: "Trigger", Value: trigger},
		{Label: "Running in", Value: strings.Join(locations, ", ") + more},
		{Label: "Method", Value: method},
		{Label: "Scanned", Value: formatTime(doc.ScannedAt)},
	}
}

func contextRows(doc Document) []pdfRow {
	c := doc.Context
	if doc.Runtime != nil {
		return runtimeRows(doc)
	}
	if !c.InCI() {
		return []pdfRow{{Label: "Run", Value: "Not run in a recognised CI system"}}
	}
	pr := ""
	if c.PullRequest > 0 {
		pr = fmt.Sprintf("#%d · %s", c.PullRequest, c.PullRequestURL)
	}
	trigger := c.Actor
	if c.Event != "" {
		trigger = fmt.Sprintf("%s (%s)", c.Actor, c.Event)
	}
	return nonEmpty([]pdfRow{
		{Label: "Repository", Value: c.Repository},
		{Label: "Commit", Value: c.Commit, Mono: true},
		{Label: "Branch", Value: c.Branch},
		{Label: "Pull request", Value: pr},
		{Label: "Workflow", Value: c.Workflow},
		{Label: "CI run", Value: c.RunURL},
		{Label: "Triggered by", Value: trigger},
		{Label: "Scanned", Value: formatTime(doc.ScannedAt)},
	})
}
