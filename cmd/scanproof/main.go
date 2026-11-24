// Command scanproof scans a container image, or software installed in a
// directory, and records the result as evidence for audits such as SOC 2.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HowardLee12/scanproof/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := app.Run(ctx, os.Args[1:], app.Env{
		Getenv: os.Getenv,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Now:    time.Now,
	})
	stop()
	os.Exit(code)
}
