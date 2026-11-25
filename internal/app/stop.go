package app

import (
	"time"

	"github.com/HowardLee12/scanproof/internal/stopped"
)

// timeoutGrace is how long a scan may run past --timeout. Trivy gets
// --timeout itself, so it can stop and report on its own first.
var timeoutGrace = time.Minute

// describedError says, in one sentence, that a scan stopped at its
// --timeout or was cancelled, instead of how the step it was in failed.
type describedError struct {
	msg string
	err error
}

func (d describedError) Error() string { return d.msg }
func (d describedError) Unwrap() error { return d.err }

// describeStop turns an error caused by the scan's context ending into
// that one sentence; other errors pass unchanged. what names the scan, such
// as "the scan" or "the rescan of this image".
func describeStop(err error, timeout time.Duration, what string) error {
	if msg, ok := stopped.Describe(err, timeout, what); ok {
		return describedError{msg: msg, err: err}
	}
	return err
}
