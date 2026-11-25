package tree

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/HowardLee12/scanproof/internal/stopped"
)

func TestDigestSaysHowFarItGotWhenStopped(t *testing.T) {
	root := makeTree(t) // three files: bin/worker, lib-a, lib/site-packages/METADATA
	ctx, cancel := context.WithCancel(context.Background())
	_, err := Digest(ctx, root, func(e Entry, r io.Reader) error {
		if e.Path == "lib-a" {
			cancel()
			_, err := io.Copy(io.Discard, r)
			return err
		}
		return nil
	})
	var s *stopped.Error
	if !errors.Is(err, context.Canceled) || !errors.As(err, &s) || s.Progress != "1 of 3 files read" {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "lib-a") {
		t.Errorf("the file the walk was at did not cause the stop: %v", err)
	}
}

func TestNotAboutFileIsNotBlamedOnTheFile(t *testing.T) {
	batch := errors.New("clamscan exited with 2 while scanning batch 1")
	_, err := Digest(context.Background(), makeTree(t), func(e Entry, r io.Reader) error {
		return NotAboutFile(batch)
	})
	if !errors.Is(err, batch) || strings.Contains(err.Error(), "bin/worker") {
		t.Fatalf("got %v", err)
	}
}

func TestDigestWithSaysHowManyFilesThereAre(t *testing.T) {
	files := -1
	res, err := DigestWith(context.Background(), makeTree(t), Options{Listed: func(n int) { files = n }})
	if err != nil || files != 3 || res.Files != 3 {
		t.Fatalf("listed %d, result %+v, %v", files, res, err)
	}
}

func TestNotAboutFileOfNilIsNil(t *testing.T) {
	if NotAboutFile(nil) != nil {
		t.Fatal("no error must stay no error")
	}
}
