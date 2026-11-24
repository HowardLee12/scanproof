package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/HowardLee12/scanproof/internal/policy"
)

const timeLayout = "2006-01-02 15:04:05 UTC"

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatTime(*t)
}

func formatBytes(n int64) string {
	switch {
	case n <= 0:
		return ""
	case n < 1_000_000:
		return fmt.Sprintf("%.1f KB", float64(n)/1_000)
	case n < 1_000_000_000:
		return fmt.Sprintf("%.1f MB", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/1_000_000_000)
	}
}

// shortDigest keeps the algorithm and the first 12 hex characters.
func shortDigest(d string) string {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) <= 12 {
		return d
	}
	return algo + ":" + hex[:12] + "…"
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

func modeDescription(m policy.Mode) string {
	if m == policy.ModeEnforce {
		return "enforce mode (violations fail the pipeline)"
	}
	return "warn mode (the pipeline continues)"
}

func scannerDescription(doc Document) string {
	desc := fmt.Sprintf("%s %s", titleCase(doc.Scanner.Name), doc.Scanner.Version)
	if db := formatTimePtr(doc.Scanner.DBUpdatedAt); db != "" {
		desc += fmt.Sprintf(" (vulnerability database updated %s)", db)
	}
	if doc.Scanner.Imported {
		desc += " (imported report; secret scanning not verified)"
	}
	return desc
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func findingStatus(exceptionID string, violation bool) string {
	switch {
	case exceptionID != "":
		return "Accepted (" + exceptionID + ")"
	case violation:
		return "Violation"
	default:
		return "Reported"
	}
}
