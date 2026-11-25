// Package app implements the scanproof command line.
package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Version is set at build time with -ldflags.
var Version = "dev"

// Exit codes.
const (
	ExitOK        = 0
	ExitViolation = 1
	ExitError     = 2
)

// Env is everything the command reads from or writes to the outside world,
// so tests can run it without touching the real environment.
type Env struct {
	Getenv     func(string) string
	Stdout     io.Writer
	Stderr     io.Writer
	Now        func() time.Time
	HTTPClient *http.Client
	// TimeoutGrace is how long a scan may run past --timeout; zero means
	// one minute. Trivy gets --timeout itself, so it can stop and report on
	// its own first.
	TimeoutGrace time.Duration
}

const defaultTimeoutGrace = time.Minute

func (e Env) timeoutGrace() time.Duration {
	if e.TimeoutGrace > 0 {
		return e.TimeoutGrace
	}
	return defaultTimeoutGrace
}

const usage = `ScanProof scans a container image, or software installed in a directory, and
records the result as evidence.

Usage:
  scanproof scan [flags] IMAGE
  scanproof scan [flags] --trivy-results FILE
  scanproof scan --dir --name NAME [--version VERSION] [flags] PATH
  scanproof rescan --store URL --inventory kubernetes|ecs|file[,...] [flags]
  scanproof report --store URL --from YYYY-MM-DD --to YYYY-MM-DD [flags]
  scanproof version

Run "scanproof <command> --help" for the flags of a command.
`

// Run executes the command line and returns the process exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return ExitError
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], env)
	case "report":
		return runReport(ctx, args[1:], env)
	case "rescan":
		return runRescan(ctx, args[1:], env)
	case "version", "--version":
		fmt.Fprintf(env.Stdout, "scanproof %s\n", Version)
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(env.Stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(env.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return ExitError
	}
}
