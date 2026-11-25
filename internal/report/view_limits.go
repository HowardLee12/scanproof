package report

import (
	"fmt"
	"time"

	"github.com/HowardLee12/scanproof/internal/stopped"
)

// malwareLimits says which limits the malware scan ran with. Results
// written before the limits were recorded have none, and nothing is shown.
func malwareLimits(m *MalwareSection) string {
	if m == nil || m.Limits == nil {
		return ""
	}
	l := m.Limits
	return fmt.Sprintf("Limits: files larger than %s are not scanned. ClamAV scans at most %s and %s of data "+
		"inside one file, such as an archive, and spends at most %s on it.",
		limitSize(l.MaxFileBytes), stopped.Plural(l.MaxArchiveFiles, "file", "files"), limitSize(l.MaxScanBytes), limitTime(l.MaxScanTimeMS))
}

// limitSize shows a size limit in MiB, the unit ClamAV and
// --malware-max-file-mb use.
func limitSize(n int64) string {
	const mib = 1 << 20
	if n <= 0 || n%mib != 0 {
		return formatBytes(n)
	}
	return stopped.Count(int(n/mib)) + " MiB"
}

// limitTime shows a time limit in whole minutes when it is one.
func limitTime(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d <= 0:
		return "no time limit"
	case d%time.Minute == 0:
		return plural(int(d/time.Minute), "minute", "minutes")
	default:
		return d.Round(time.Second).String()
	}
}
