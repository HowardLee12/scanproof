package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestS3StoreAgainstRealService runs when SCANPROOF_S3_TEST_ENDPOINT points at
// an S3-compatible server (CI starts RustFS). It needs AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY and AWS_REGION as well.
func TestS3StoreAgainstRealService(t *testing.T) {
	endpoint := os.Getenv("SCANPROOF_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("SCANPROOF_S3_TEST_ENDPOINT is not set")
	}
	t.Setenv("AWS_ENDPOINT_URL_S3", endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	bucket := fmt.Sprintf("scanproof-test-%d", time.Now().UnixNano())
	st, err := Open(ctx, "s3://"+bucket+"/team?path-style=true")
	if err != nil {
		t.Fatal(err)
	}
	s3st := st.(*S3Store)
	if _, err := s3st.client.(*s3.Client).CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	keys := []string{"scans/2026/11/24/SR-1/results.json", "scans/2026/11/24/SR-2/results.json", "scans/2026/11/25/SR-3/results.json"}
	for _, k := range keys {
		if err := st.Put(ctx, k, []byte(`{"key":"`+k+`"}`), "application/json"); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	got, err := st.Get(ctx, keys[0])
	if err != nil || !strings.Contains(string(got), keys[0]) {
		t.Fatalf("get: %q, %v", got, err)
	}
	listed, err := st.List(ctx, "scans/2026/11/24/")
	if err != nil || strings.Join(listed, ",") != strings.Join(keys[:2], ",") {
		t.Fatalf("list: %v, %v", listed, err)
	}
	if err := st.Put(ctx, keys[0], []byte("replaced"), "application/json"); err == nil {
		t.Fatal("the service accepted a second write to the same key; write-once is not enforced")
	}
}
