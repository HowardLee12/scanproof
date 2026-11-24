package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/HowardLee12/scanproof/internal/inventory"
	"github.com/HowardLee12/scanproof/internal/notify"
	"github.com/HowardLee12/scanproof/internal/policy"
)

// maxRescanLines bounds the list in the run's chat message.
const maxRescanLines = 10

// maxReasonChars bounds one failure reason in the chat message.
const maxReasonChars = 200

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// sendRescanNotification posts one summary for the whole run.
func sendRescanNotification(ctx context.Context, opts rescanOptions, env Env, outcomes []rescanOutcome) {
	verdict, lines := rescanAttention(outcomes)
	if !notify.ShouldNotify(opts.Notify, verdict) {
		return
	}
	targets := notify.TargetsFromEnv(env.Getenv)
	if len(targets) == 0 {
		return
	}
	shown, more := lines, 0
	if len(shown) > maxRescanLines {
		shown, more = lines[:maxRescanLines], len(lines)-maxRescanLines
	}
	checked := make([]inventory.RunningImage, 0, len(outcomes))
	for _, o := range outcomes {
		if o.where == "" {
			checked = append(checked, o.image)
		}
	}
	msg := notify.Message{
		Verdict:        verdict,
		Title:          fmt.Sprintf("ScanProof rescan: %d of %s need attention", len(lines), countPhrase(checked, "running ")),
		Summary:        fmt.Sprintf("Rescanned %s against today's vulnerability database", countPhrase(checked, "running ")),
		Violations:     shown,
		MoreViolations: more,
		ReportID:       "rescan " + env.Now().UTC().Format("2006-01-02"),
	}
	client := env.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: notifyTimeout}
	}
	sender := notify.Sender{Client: client, UserAgent: "scanproof/" + Version + " (+https://github.com/HowardLee12/scanproof)"}
	for _, t := range targets {
		if err := sender.Send(ctx, t, msg); err != nil {
			fmt.Fprintf(env.Stderr, "scanproof: warning: %s notification failed: %v\n", t.Name, err)
		}
	}
}

// rescanAttention lists the images and directories that have violations or
// could not be rescanned, and the run's verdict.
func rescanAttention(outcomes []rescanOutcome) (policy.Verdict, []string) {
	verdict := policy.VerdictPass
	lines := []string{}
	for _, o := range outcomes {
		var stored *storedScanError
		switch {
		case errors.Is(o.err, errNoDirectoryScan):
			verdict = policy.VerdictWarn
			lines = append(lines, o.label()+": no stored scan; run scanproof scan --dir on a host that has it")
		case errors.As(o.err, &stored), o.err != nil && o.where != "":
			verdict = policy.VerdictWarn
			lines = append(lines, o.label()+": "+shorten(o.err.Error(), maxReasonChars))
		case o.err != nil:
			verdict = policy.VerdictWarn
			lines = append(lines, o.label()+": scan failed")
		case o.doc.Summary.Violations > 0:
			verdict = policy.VerdictWarn
			lines = append(lines, fmt.Sprintf("%s: %d violations", o.image.Label(), o.doc.Summary.Violations))
		}
	}
	return verdict, lines
}
