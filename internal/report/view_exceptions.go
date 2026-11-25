package report

import (
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/exception"
)

func exceptionRows(list []exception.Exception) [][]string {
	rows := make([][]string, 0, len(list))
	for _, ex := range list {
		finding := ex.Finding
		if ex.Package != "" {
			finding += " in " + ex.Package
		}
		if scope := ex.Scope(); scope != "" {
			finding += ", " + scope
		}
		approver := ex.ApprovedBy
		if approver == "" {
			approver = "See the pull request that added it"
		}
		rows = append(rows, []string{ex.ID, finding, ex.Reason, approver, ex.Expires.String()})
	}
	return rows
}

// outOfScopeText says how many exceptions in the file apply only to other
// images and directories, so they do not vanish from the evidence.
func outOfScopeText(o *OutOfScope) string {
	if o == nil || o.Count == 0 {
		return ""
	}
	text := plural(o.Count, "exception in the file applies", "exceptions in the file apply") +
		" only to other images or directories"
	if len(o.IDs) > 0 {
		text += " (" + strings.Join(o.IDs, ", ") + ")"
	}
	return text + "."
}

// exceptionsFileLabel names the exceptions file and its hash for the job
// summary's footer; "" when no file was used.
func exceptionsFileLabel(e Exceptions) string {
	if e.Source == "" {
		return ""
	}
	label := e.Source
	if e.SHA256 != "" {
		label += fmt.Sprintf(" (sha256:%s…)", e.SHA256[:min(12, len(e.SHA256))])
	}
	return label
}
