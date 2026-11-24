package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3API is the part of the S3 client the store uses, so tests can fake it.
type s3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// S3Store keeps evidence in an S3 or S3-compatible bucket.
type S3Store struct {
	client   s3API
	bucket   string
	prefix   string
	checksum bool
	// allowOverwrite turns off the write-once check, for S3-compatible
	// services that do not support conditional writes.
	allowOverwrite bool
}

type s3Config struct {
	bucket    string
	prefix    string
	pathStyle bool
	checksum  bool
	writeOnce bool
}

// parseS3URL reads s3://bucket/prefix?path-style=true&checksum=false&write-once=false.
func parseS3URL(raw string) (s3Config, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" {
		return s3Config{}, fmt.Errorf("invalid S3 store URL %q (want s3://bucket/prefix)", raw)
	}
	cfg := s3Config{bucket: u.Host, checksum: true, writeOnce: true}
	if p := strings.Trim(u.Path, "/"); p != "" {
		cfg.prefix = p + "/"
	}
	options := map[string]*bool{"path-style": &cfg.pathStyle, "checksum": &cfg.checksum, "write-once": &cfg.writeOnce}
	for name, values := range u.Query() {
		target, ok := options[name]
		if !ok {
			return s3Config{}, fmt.Errorf("unknown S3 store option %q (known: path-style, checksum, write-once)", name)
		}
		v, err := strconv.ParseBool(values[0])
		if err != nil {
			return s3Config{}, fmt.Errorf("S3 store option %s=%q must be true or false", name, values[0])
		}
		*target = v
	}
	return cfg, nil
}

// openS3 uses the standard AWS configuration chain: AWS_REGION, AWS_PROFILE,
// web identity (GitHub OIDC), instance roles, and AWS_ENDPOINT_URL_S3 for
// S3-compatible services.
func openS3(ctx context.Context, raw string) (*S3Store, error) {
	cfg, err := parseS3URL(raw)
	if err != nil {
		return nil, err
	}
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.pathStyle
		if !cfg.checksum {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		}
	})
	return &S3Store{client: client, bucket: cfg.bucket, prefix: cfg.prefix, checksum: cfg.checksum, allowOverwrite: !cfg.writeOnce}, nil
}

// Put uploads data. With write-once (the default) it fails if the key exists.
func (s *S3Store) Put(ctx context.Context, key string, data []byte, contentType string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	in := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.prefix + key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	}
	if s.checksum {
		// Buckets with Object Lock reject uploads without a checksum.
		in.ChecksumAlgorithm = types.ChecksumAlgorithmSha256
	}
	if !s.allowOverwrite {
		in.IfNoneMatch = aws.String("*")
	}
	if _, err := s.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("upload %s: %w", s.Location(key), err)
	}
	return nil
}

// Get downloads key.
func (s *S3Store) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(s.prefix + key)})
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", s.Location(key), err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", s.Location(key), err)
	}
	return data, nil
}

// List returns the keys under prefix, sorted, following every result page.
func (s *S3Store) List(ctx context.Context, prefix string) ([]string, error) {
	keys := make([]string, 0)
	in := &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(s.prefix + prefix)}
	for {
		out, err := s.client.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", s.Location(prefix), err)
		}
		for _, obj := range out.Contents {
			keys = append(keys, strings.TrimPrefix(aws.ToString(obj.Key), s.prefix))
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.ContinuationToken = out.NextContinuationToken
	}
	sortStrings(keys)
	return keys, nil
}

// Location returns the s3:// URL of key.
func (s *S3Store) Location(key string) string {
	return "s3://" + s.bucket + "/" + s.prefix + key
}
