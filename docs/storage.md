# Evidence storage

ScanProof writes every scan to an evidence store, and the period summary reads the scans back from it. This page explains how to set one up.

You need a store if you want:

- a **period summary** (`scanproof report`), which reads every scan in the period from the store
- **rescans** of running images, which reuse the SBOM saved at build time
- evidence that lasts longer than CI artifacts (GitHub keeps them for 90 days by default)

Without `--store`, ScanProof only writes files to the local output directory.

## What is stored

Each scan is saved under the UTC day it ran:

```
<prefix>/scans/2026/11/24/SR-20261124-7F3A9C/
    results.json      every finding, the policy result and the CI context
    summary.md        the job summary
    report.pdf        the auditor report (when Typst is available)
    sbom.cdx.json     the image's packages, used by rescans
    manifest.json     SHA-256 of every file above

<prefix>/index/digests/sha256/<digest>/SR-20261124-7F3A9C.json
                      points from the image digest to the scan, so a rescan
                      can find the newest SBOM without listing every day
```

With `--save`, period summaries are saved next to the scans:

```
<prefix>/summaries/2026-07-01_2026-09-30/PS-20261001-ABC123/
    summary.json  population.csv  summary.md  summary.pdf  manifest.json
```

The store is **write-once**. ScanProof never overwrites or deletes anything. Every upload uses a conditional write (`If-None-Match: *`), so the store rejects a second write to the same key.

## Store URLs

| URL | Store |
|---|---|
| `s3://BUCKET/PREFIX` | Amazon S3 |
| `s3://BUCKET/PREFIX?path-style=true` | S3-compatible service that needs path-style requests (for example MinIO, RustFS) |
| `file:///var/evidence` | Local or mounted directory |

`PREFIX` is optional. Use it to keep several teams or environments in one bucket, for example `s3://acme-evidence/prod`.

Options for S3 URLs:

| Option | Default | When to change it |
|---|---|---|
| `path-style` | `false` | Set `true` when the service needs `https://host/bucket/key` requests |
| `checksum` | `true` | Set `false` only if the service rejects SHA-256 upload checksums. Buckets with Amazon S3 Object Lock need checksums. |
| `write-once` | `true` | Set `false` only if the service does not support conditional writes. Use the service's own retention or locking instead. |

## Amazon S3

### 1. Create the bucket

Object Lock can only be turned on when the bucket is created.

```sh
aws s3api create-bucket \
  --bucket acme-scan-evidence \
  --region us-east-2 \
  --create-bucket-configuration LocationConstraint=us-east-2 \
  --object-lock-enabled-for-bucket

aws s3api put-public-access-block \
  --bucket acme-scan-evidence \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

New S3 buckets encrypt objects with SSE-S3 by default. To use a KMS key instead, set default encryption with `aws s3api put-bucket-encryption`.

### 2. Set a retention period

```sh
aws s3api put-object-lock-configuration \
  --bucket acme-scan-evidence \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": { "DefaultRetention": { "Mode": "GOVERNANCE", "Years": 2 } }
  }'
```

- **Governance mode** blocks deletes unless a user has `s3:BypassGovernanceRetention`. Start here while you test.
- **Compliance mode** blocks deletes for everyone, including the account root user, until retention ends. The retention can't be shortened, so switch to it only once the setup works.
- Keep evidence for at least your audit period plus the time the audit takes. Two years covers an annual SOC 2 Type 2 cycle with room to spare.

### 3. Refuse unencrypted connections

```sh
aws s3api put-bucket-policy --bucket acme-scan-evidence --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::acme-scan-evidence", "arn:aws:s3:::acme-scan-evidence/*"],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }]
}'
```

### 4. Permissions

Give CI and the summary job separate roles, each with only what it needs.

**CI role (writes scans)**:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::acme-scan-evidence/prod/scans/*"
  }]
}
```

Rescans also read and write the digest index that points to stored SBOMs, so give a rescan job `s3:ListBucket` on `prod/index/*` and `prod/scans/*`, `s3:GetObject` on both, and `s3:PutObject` on both.

**Summary role (reads scans, saves summaries)**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::acme-scan-evidence",
      "Condition": { "StringLike": { "s3:prefix": "prod/scans/*" } }
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::acme-scan-evidence/prod/scans/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-scan-evidence/prod/summaries/*"
    }
  ]
}
```

Drop the last statement if you don't use `--save`. Neither role needs `s3:DeleteObject`, and neither should have it.

If the bucket uses a customer-managed KMS key, also allow `kms:GenerateDataKey` (writers) and `kms:Decrypt` (readers) on that key.

### 5. Credentials

ScanProof uses the standard AWS credential chain:

- environment variables
- `AWS_PROFILE`
- web identity, for example GitHub OIDC
- ECS task roles and EC2 instance roles

Set `AWS_REGION` to the bucket's region.

For GitHub Actions, use OIDC instead of access keys. Create an IAM role that trusts GitHub's OIDC provider, limited to your repository:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main"
    }
  }
}
```

If the job uses a GitHub environment (`environment: production`), the subject is `repo:acme/api:environment:production` instead.

Then in the workflow:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/scanproof-ci
      aws-region: us-east-2

  - uses: HowardLee12/scanproof@v0.1.0
    with:
      image: example-api:${{ github.sha }}
      store: s3://acme-scan-evidence/prod
```

## S3-compatible services

ScanProof talks to any service that implements the S3 API. Point the AWS SDK at the service with environment variables:

| Variable | Value |
|---|---|
| `AWS_ENDPOINT_URL_S3` | The service's S3 endpoint |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Access key for the bucket |
| `AWS_REGION` | The region the service expects |

Find the endpoint and region in your provider's documentation. Before you rely on the service for evidence, check two things:

1. **Conditional writes.** Run a test scan twice and confirm both uploads succeed. Then try to write an existing key with `aws s3api put-object --if-none-match '*'` and confirm the service refuses it. If it does not support conditional writes, add `write-once=false` and use the service's own retention or bucket lock.
2. **Retention.** Check whether the service supports S3 Object Lock or its own retention lock. If it supports neither, enable versioning and give no client permission to delete.

Examples:

```sh
# MinIO or RustFS on your own network
export AWS_ENDPOINT_URL_S3=https://s3.internal.example:9000
export AWS_REGION=us-east-1
scanproof scan --store "s3://evidence/prod?path-style=true" example-api:1.0

# Cloudflare R2
export AWS_ENDPOINT_URL_S3=https://ACCOUNT_ID.r2.cloudflarestorage.com
export AWS_REGION=auto
scanproof scan --store "s3://evidence/prod" example-api:1.0
```

ScanProof's tests run against RustFS, which supports conditional writes and SHA-256 checksums.

## Local directory

```sh
scanproof scan --store file:///mnt/evidence example-api:1.0
```

A directory store is useful for trying ScanProof out, and for small setups that back up a mounted volume. It refuses to overwrite files, but it does not stop anyone with file system access from deleting or editing them. Don't use it as your only audit evidence.

## Period summary

```sh
scanproof report \
  --store s3://acme-scan-evidence/prod \
  --from 2026-07-01 --to 2026-09-30 \
  --policy .scanproof/policy.yaml \
  --save
```

- `--from` and `--to` are UTC dates, both included.
- `--lookback-days` (default 90) also reads scans from before the period. A finding that was already open on day one then gets its real first-seen date, so its SLA deadline is right.
- `--policy` supplies `sla_days`. Without it, Critical, High and Medium findings get 15, 30 and 90 days.
- `--save` stores the summary in the bucket as well, under `summaries/`.
- A scan counts only once its `manifest.json` exists, because the manifest is uploaded last. Folders without one, left by an interrupted upload, are listed in the summary as incomplete. A `results.json` that doesn't match the SHA-256 in its manifest stops the summary with an error.
- Open findings are judged when the summary runs. If you make a summary before the period ends, a finding counts as overdue only if its deadline has already passed.

The summary needs one `List` request per day of the period plus the look-back window. It then needs one `Get` request per scan.
