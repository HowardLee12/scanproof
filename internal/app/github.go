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
	line := fmt.Sprintf("ScanProof %s: %s · %d policy violations · %s mode · report %s · evidence in %s",
		doc.Verdict, doc.Image.Reference, doc.Summary.Violations, doc.Policy.Mode, doc.ReportID, where)
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
