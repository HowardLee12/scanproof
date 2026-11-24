package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/HowardLee12/scanproof/internal/policy"
	"github.com/HowardLee12/scanproof/internal/report"
)

// announce prints a one-line result and, in GitHub Actions, an annotation
// that appears on the workflow run page.
func announce(env Env, doc report.Document, outDir, location string) {
	where := outDir
	if location != "" {
		where = location
	}
	violations := fmt.Sprintf("%d policy violations", doc.Summary.Violations)
	if doc.Summary.Violations == 1 {
		violations = "1 policy violation"
	}
	line := fmt.Sprintf("ScanProof %s: %s · %s · %s mode · report %s · evidence in %s",
		doc.Verdict, report.ArtifactLabel(doc), violations, doc.Policy.Mode, doc.ReportID, where)
	fmt.Fprintln(env.Stdout, line)

	if env.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}
	switch doc.Verdict {
	case policy.VerdictWarn:
		fmt.Fprintf(env.Stdout, "::warning title=ScanProof::%s\n", escapeAnnotation(line))
	case policy.VerdictFail:
		fmt.Fprintf(env.Stdout, "::error title=ScanProof::%s\n", escapeAnnotation(line))
	}
}

// announceInventoryLine prints, after a directory scan, the line to add to
// the rescan images file, or why rescans cannot check the directory.
func announceInventoryLine(env Env, doc report.Document, indexed bool) {
	if !doc.IsDirectory() {
		return
	}
	if !indexed {
		fmt.Fprintln(env.Stdout, "This scan was not stored with an SBOM, so scanproof rescan cannot check this directory; "+
			"scan it with --store (and without --sbom=false) to rescan it.")
		return
	}
	fmt.Fprintf(env.Stdout, "Rescan inventory line: %s@%s\n", doc.Image.Reference, doc.Image.Digest)
}

// escapeAnnotation encodes characters that GitHub workflow commands reserve.
func escapeAnnotation(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func writeGitHubStepSummary(env Env, path, summary string) {
	if path == "" {
		return
	}
	if err := appendFile(path, summary+"\n"); err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: warning: could not write the job summary: %v\n", err)
	}
}

// writeGitHubOutputs exposes the result to later workflow steps.
func writeGitHubOutputs(env Env, doc report.Document, outDir, location string) {
	path := env.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return
	}
	lines := []string{
		"verdict=" + string(doc.Verdict),
		"report-id=" + doc.ReportID,
		fmt.Sprintf("violations=%d", doc.Summary.Violations),
		"results=" + filepath.Join(outDir, resultsFile),
		"evidence-dir=" + outDir,
	}
	if location != "" {
		lines = append(lines, "evidence-url="+location)
	}
	if err := appendFile(path, strings.Join(lines, "\n")+"\n"); err != nil {
		fmt.Fprintf(env.Stderr, "scanproof: warning: could not write step outputs: %v\n", err)
	}
}

func appendFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(text)
	return err
}
