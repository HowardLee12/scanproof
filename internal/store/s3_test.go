package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3 keeps objects in memory and pages List results two at a time.
type fakeS3 struct {
	objects map[string][]byte
	puts    []*s3.PutObjectInput
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]byte{}} }

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if aws.ToString(in.IfNoneMatch) == "*" {
		if _, exists := f.objects[aws.ToString(in.Key)]; exists {
			return nil, errors.New("PreconditionFailed")
		}
	}
	data, _ := io.ReadAll(in.Body)
	f.objects[aws.ToString(in.Key)] = data
	f.puts = append(f.puts, in)
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	data, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	keys := []string{}
	for k := range f.objects {
		if strings.HasPrefix(k, aws.ToString(in.Prefix)) {
			keys = append(keys, k)
		}
	}
	sortStrings(keys)
	start := 0
	if in.ContinuationToken != nil {
		for i, k := range keys {
			if k == aws.ToString(in.ContinuationToken) {
				start = i
			}
		}
	}
	end := start + 2
	out := &s3.ListObjectsV2Output{}
	if end < len(keys) {
		out.IsTruncated = aws.Bool(true)
		out.NextContinuationToken = aws.String(keys[end])
	} else {
		end = len(keys)
	}
	for _, k := range keys[start:end] {
		out.Contents = append(out.Contents, types.Object{Key: aws.String(k)})
	}
	return out, nil
}

func TestS3StoreUsesPrefixAndChecksum(t *testing.T) {
	fake := newFakeS3()
	s := &S3Store{client: fake, bucket: "evidence", prefix: "team-a/", checksum: true}
	ctx := context.Background()

	if err := s.Put(ctx, "scans/2026/11/24/SR-1/results.json", []byte("{}"), "application/json"); err != nil {
		t.Fatal(err)
	}
	in := fake.puts[0]
	if aws.ToString(in.Key) != "team-a/scans/2026/11/24/SR-1/results.json" || aws.ToString(in.Bucket) != "evidence" {
		t.Errorf("wrong location %s/%s", aws.ToString(in.Bucket), aws.ToString(in.Key))
	}
	if in.ChecksumAlgorithm != types.ChecksumAlgorithmSha256 {
		t.Error("S3 Object Lock requires a checksum on every upload")
	}
	if aws.ToString(in.ContentType) != "application/json" || aws.ToString(in.IfNoneMatch) != "*" {
		t.Errorf("content type %q, if-none-match %q", aws.ToString(in.ContentType), aws.ToString(in.IfNoneMatch))
	}

	got, err := s.Get(ctx, "scans/2026/11/24/SR-1/results.json")
	if err != nil || string(got) != "{}" {
		t.Fatalf("got %q, %v", got, err)
	}
	if s.Location("scans/x") != "s3://evidence/team-a/scans/x" {
		t.Errorf("location = %q", s.Location("scans/x"))
	}
}

func TestS3StoreListFollowsPagesAndStripsPrefix(t *testing.T) {
	fake := newFakeS3()
	for _, k := range []string{"p/scans/a", "p/scans/b", "p/scans/c", "p/scans/d", "p/scans/e", "p/other/x"} {
		fake.objects[k] = []byte("x")
	}
	s := &S3Store{client: fake, bucket: "b", prefix: "p/"}
	keys, err := s.List(context.Background(), "scans/")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "scans/a,scans/b,scans/c,scans/d,scans/e" {
		t.Fatalf("got %v", keys)
	}
}

func TestS3StoreWithoutChecksum(t *testing.T) {
	fake := newFakeS3()
	s := &S3Store{client: fake, bucket: "b"}
	if err := s.Put(context.Background(), "k", []byte("x"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if fake.puts[0].ChecksumAlgorithm != "" {
		t.Error("checksum=false must not send a checksum algorithm")
	}
}

func TestS3StoreRejectsSecondWrite(t *testing.T) {
	fake := newFakeS3()
	s := &S3Store{client: fake, bucket: "b"}
	ctx := context.Background()
	if err := s.Put(ctx, "k", []byte("1"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "k", []byte("2"), "text/plain"); err == nil {
		t.Fatal("evidence is write-once")
	}
}

func TestParseS3URL(t *testing.T) {
	cfg, err := parseS3URL("s3://my-bucket/evidence/prod?path-style=true&checksum=false")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.bucket != "my-bucket" || cfg.prefix != "evidence/prod/" || !cfg.pathStyle || cfg.checksum {
		t.Fatalf("unexpected %+v", cfg)
	}
	cfg, err = parseS3URL("s3://bucket")
	if err != nil || cfg.prefix != "" || cfg.pathStyle || !cfg.checksum {
		t.Fatalf("defaults wrong: %+v %v", cfg, err)
	}
	if _, err := parseS3URL("s3://bucket?path-style=maybe"); err == nil {
		t.Fatal("expected an error for a bad option")
	}
	if _, err := parseS3URL("s3://bucket?unknown=1"); err == nil {
		t.Fatal("expected an error for an unknown option")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
