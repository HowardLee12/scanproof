package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/HowardLee12/scanproof/internal/model"
)

// maxCoverageRows bounds the coverage tables; results.json has the rest.
const maxCoverageRows = 20

// coverageOf returns a directory scan's coverage gaps, or nil.
func coverageOf(doc Document) *model.Coverage {
	if doc.Directory == nil || doc.Directory.Coverage == nil {
		return nil
	}
	c := doc.Directory.Coverage
	if c.NotScanned.Files+c.SecretsNotChecked.Files == 0 {
		return nil
	}
	return c
}

// notCheckedSummary is one line for the directory table.
func notCheckedSummary(c *model.Coverage) string {
	if c == nil {
		return ""
	}
	parts := []string{}
	if n := c.NotScanned.Files; n > 0 {
		parts = append(parts, plural(n, "file", "files")+" not checked for vulnerabilities or secrets")
	}
	if n := c.SecretsNotChecked.Files; n > 0 {
		parts = append(parts, plural(n, "file", "files")+" not checked for secrets")
	}
	return strings.Join(parts, " · ") + " (see Coverage)"
}

func notScannedRows(c *model.Coverage) [][]string {
	if c == nil {
		return [][]string{}
	}
	rows := make([][]string, 0, len(c.NotScanned.Paths))
	for _, p := range c.NotScanned.Paths {
		rows = append(rows, []string{p.Path, strconv.Itoa(p.Files), p.Reason})
	}
	if c.NotScanned.Omitted > 0 {
		rows = append(rows, []string{fmt.Sprintf("%d more in results.json", c.NotScanned.Omitted), "", ""})
	}
	return rows
}

func secretsSkippedRows(c *model.Coverage) [][]string {
	if c == nil {
		return [][]string{}
	}
	paths := c.SecretsNotChecked.Paths
	shown := paths[:min(len(paths), maxCoverageRows)]
	rows := make([][]string, 0, len(shown)+1)
	for _, p := range shown {
		rows = append(rows, []string{p.Path, p.Reason})
	}
	if more := c.SecretsNotChecked.Omitted + len(paths) - len(shown); more > 0 {
		rows = append(rows, []string{fmt.Sprintf("%d more in results.json", more), ""})
	}
	return rows
}

func secretsSkippedNote(c *model.Coverage) string {
	if c == nil || c.SecretsNotChecked.Files == 0 {
		return ""
	}
	return fmt.Sprintf("Trivy's secret scanner does not read %s: %s. They were still checked for known "+
		"vulnerabilities where Trivy recognises them as packages.",
		plural(c.SecretsNotChecked.Files, "file", "files"), byReason(c.SecretsNotChecked.ByReason))
}

// byReason lists counts, largest first: "binary file 100, file type .bin 20".
func byReason(counts map[string]int) string {
	reasons := make([]string, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, fmt.Sprintf("%s %d", r, counts[r]))
	}
	return strings.Join(parts, ", ")
}

// secretsNone is the note when no secret was found. It never claims that
// every file was read.
func secretsNone(doc Document) string {
	if doc.IsDirectory() {
		note := "No keys, tokens or passwords were found in the files Trivy's secret scanner reads."
		if coverageOf(doc) != nil {
			note += " The files it does not read are listed under Coverage."
		}
		return note
	}
	return "No keys, tokens or passwords were found in the files Trivy's secret scanner reads. It skips binary files, " +
		"some file types (such as images and archives), lock files, and .git, node_modules and vendor directories."
}

// pick returns yes when cond holds, otherwise no.
func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
