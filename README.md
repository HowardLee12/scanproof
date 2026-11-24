# ScanProof

ScanProof scans a container image in CI, or software installed in a directory, and keeps the result as evidence you can hand to an auditor.

It runs [Trivy](https://github.com/aquasecurity/trivy) for vulnerabilities and embedded secrets, and optionally [ClamAV](https://www.clamav.net/) and YARA for malware. It then applies a policy and your approved exceptions, and writes:

| File | For |
|---|---|
| `results.json` | Every finding, the policy result and the CI context, in one machine-readable file |
| `summary.md` | The GitHub Actions job summary |
| `report.pdf` | A short report for auditors: verdict, image digest (or directory and tree digest), change, findings, exceptions |
| `manifest.json` | SHA-256 of each file, so anyone can check later that nothing was changed |

It can also post the result to Discord or Slack, keep every scan in an S3 bucket, and turn a quarter of stored scans into a **period summary** for auditors: coverage, remediation against your SLA, and the full list of scans to sample from.

ScanProof does not replace your scanner or your registry's scanning. It answers a different question: for every image you deployed, was it checked before release, what was known at the time, and can you prove it?

## Quick start

### GitHub Actions

```yaml
- name: Scan
  uses: HowardLee12/scanproof@v0.1.0
  with:
    image: example-api:${{ github.sha }}   # an image built earlier in the job, or a registry reference
    exceptions: .scanproof/exceptions.yaml
    mode: warn
  env:
    SCANPROOF_DISCORD_WEBHOOK_URL: ${{ secrets.SCANPROOF_DISCORD_WEBHOOK_URL }}
```

A full workflow is in [examples/github-workflow.yml](examples/github-workflow.yml).

### Docker

```sh
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/evidence:/out" \
  ghcr.io/howardlee12/scanproof:latest scan --out /out alpine:3.18.0
```

### Existing Trivy output

If your pipeline already runs Trivy, pass its JSON report instead of scanning again:

```sh
trivy image --format json --output trivy.json my-image:1.0
scanproof scan --trivy-results trivy.json --out evidence
```

## Keeping evidence and period summaries

Add `--store` (or the `store` input of the action) to upload every scan to an S3 bucket, an S3-compatible service, or a directory:

```sh
scanproof scan --store s3://acme-scan-evidence/prod example-api:1.0
```

At the end of a period, build the summary an auditor asks for:

```sh
scanproof report --store s3://acme-scan-evidence/prod --from 2026-07-01 --to 2026-09-30 --save
```

It writes `summary.pdf`, `summary.json`, `summary.md` and `population.csv` (one row per scan, for sampling). Each finding is followed from the first scan that reports it until scans of that image no longer do, and is measured against the `sla_days` in your policy. Scans of the same image on the same day are combined, so an image running in two places only counts as fixed when every copy is. A finding that comes back keeps its original deadline. Findings closed by an exception are reported separately and never count as fixed.

To check what is **running now** against today's vulnerability data, run a daily rescan. It finds running images in Kubernetes, Amazon ECS or a list, checks each one's stored SBOM (no image pull), stores the results with the build-time scans, and posts one summary to chat:

```sh
scanproof rescan --store s3://acme-scan-evidence/prod --inventory kubernetes
```

**[docs/rescan.md](docs/rescan.md)** has a ready-to-apply Kubernetes CronJob and RBAC rules, and the ECS setup.

## Directories

Some software runs from a directory rather than an image, for example a Python virtualenv on a shared filesystem that GPU pods load at startup. Scan each version once on a machine that has it:

```sh
scanproof scan --dir --name acme-vllm --version 0.9.1 --store s3://acme-scan-evidence/prod /mnt/shared/venvs/vllm
```

The directory is identified by a tree digest of its names, contents, permissions and symlinks, and the evidence is stored like an image scan. List it in the rescan images file as `dir:acme-vllm:0.9.1@sha256:<tree digest>`, and `scanproof rescan --inventory kubernetes,file` checks its stored SBOM every day without access to the directory. **[docs/directories.md](docs/directories.md)** covers the tree digest algorithm, malware checks, and a Kubernetes Job that scans a directory only GPU nodes mount.

**[docs/storage.md](docs/storage.md)** explains how to set up the bucket: Object Lock retention, least-privilege IAM for CI and for the summary job, GitHub OIDC, S3-compatible services and their settings.

## Malware

```sh
scanproof scan --malware example-api:1.0
```

Checks every file in the image (or the directory, with `--dir`) with ClamAV, plus YARA when you pass `--yara-rules`. Use the `-full` image, which includes both engines. **[docs/malware.md](docs/malware.md)** covers keeping the signatures current, YARA rules, exceptions, and the limits.

## Policy

Without a policy file, ScanProof **warns** about fixable Critical vulnerabilities and about any embedded secret. Start in warn mode, look at what it finds for a couple of weeks, then switch to enforce.

```yaml
# .scanproof/policy.yaml
mode: warn            # warn | enforce
fail_on:
  severity: CRITICAL  # lowest severity that counts as a violation
  fixable_only: true  # only count vulnerabilities that have a fix
  secrets: true       # count every embedded secret
  malware: true       # count every malware detection (with --malware)
  unscanned_files: true  # count files the malware scan could not fully read
sla_days:             # remediation deadlines used by period summaries
  critical: 15
  high: 30
  medium: 90
```

| Verdict | Meaning | Exit code |
|---|---|---|
| `PASS` | No violations | 0 |
| `WARN` | Violations in warn mode | 0 |
| `FAIL` | Violations in enforce mode | 1 |

Invalid input or a scan failure exits with 2.

## Exceptions

Some findings cannot be fixed yet. Record them in the repository so the pull request that adds each one is the approval:

```yaml
# .scanproof/exceptions.yaml
exceptions:
  - id: EX-2026-004
    finding: CVE-2023-45853       # CVE ID or secret rule ID
    package: zlib1g               # optional
    reason: MiniZip is not built into Debian's zlib1g; no fixed version is available.
    approved_by: security-lead
    expires: 2027-02-28
```

For a secret, give the secret rule ID and the file it is in. An exception for a secret always needs `path`, so accepting a fake key in a test fixture never accepts a real key somewhere else:

```yaml
  - id: EX-2026-005
    finding: aws-access-key-id
    path: app/tests/fixtures/fake.ini
    reason: Documented example key used by tests.
    expires: 2026-12-31
```

Every exception must have a reason and an expiry date. After it expires, the finding counts again and the report lists the exception as expired. Exceptions that match nothing are listed as unused, so stale ones are easy to clean up.

## Notifications

Set either or both webhook URLs as secrets:

- `SCANPROOF_DISCORD_WEBHOOK_URL`
- `SCANPROOF_SLACK_WEBHOOK_URL`

`--notify` controls when to post: `violation` (default), `always` or `never`. Webhook URLs must use HTTPS and never appear in logs or error messages. Discord messages cannot ping `@everyone` or anyone else, whatever the image or package names contain.

## Command-line flags

```
scanproof scan [flags] IMAGE
scanproof scan --dir --name NAME [--version VERSION] [flags] PATH

  --dir                  scan the directory PATH instead of an image
  --name NAME            with --dir: the name the directory is tracked by (required)
  --version VERSION      with --dir: the version of the software in it
  --policy FILE          policy file (default: built-in policy)
  --exceptions FILE      exceptions file
  --mode warn|enforce    overrides the policy file
  --out DIR              output directory (default scanproof-out)
  --pdf=false            skip report.pdf
  --sbom=false           skip sbom.cdx.json
  --store URL            upload evidence to s3://bucket/prefix or file:///path
  --malware              also scan every file for malware (-full image)
  --yara-rules PATH      YARA rule file or directory (with --malware)
  --clamav-db DIR        ClamAV signature directory or file
  --clamav-update        run freshclam before the malware scan
  --malware-max-file-mb  skip larger files, listed in the report (default 512)
  --platform OS/ARCH     image platform for multi-platform images (not with --dir)
  --notify WHEN          violation | always | never (default violation)
  --trivy-results FILE   use an existing Trivy JSON report (not with --dir)
  --trivy PATH           trivy binary (default trivy)
  --typst PATH           typst binary used for the PDF (default typst)
  --timeout DURATION     scan time limit (default 30m)
```

In GitHub Actions, ScanProof also appends the summary to the job page, adds a warning or error annotation, and sets the step outputs `verdict`, `report-id`, `violations`, `results`, `evidence-dir` and, with a store, `evidence-url`.

```
scanproof rescan --store URL --inventory kubernetes|ecs|file[,...] [flags]
```

See [docs/rescan.md](docs/rescan.md) for the rescan flags.

```
scanproof report --store URL --from YYYY-MM-DD --to YYYY-MM-DD [flags]

  --lookback-days N      also read N days before the period (default 90)
  --policy FILE          policy file with sla_days
  --out DIR              output directory (default scanproof-summary)
  --pdf=false            skip summary.pdf
  --save                 also save the summary to the store
```

## SOC 2

The PDF maps the report to SOC 2 criteria CC7.1 and CC8.1 for convenience. Your auditor decides whether the evidence is sufficient.

## Security notes

- Trivy settings files in the working directory, such as the scanned repository (`trivy.yaml`, `.trivyignore`, `trivy-secret.yaml`), and `TRIVY_*` variables that filter results are ignored. Image scans use Trivy's built-in secret rules, whose allow rules skip paths such as tests, examples and system directories (the report lists them); directory scans switch those allow rules off. The only way to accept a finding is an exception with a reason and an expiry date. Registry login, cache and database mirror variables are still passed through.
- Imported Trivy reports (`--trivy-results`) must come from `trivy image`, and the report says that secret scanning could not be verified.
- Secret findings record the rule, file and line only. The matched text is never stored or printed.
- Values from scan results are passed to the PDF template as data, never as template code.
- The image pins Trivy by digest and verifies the Typst download by SHA-256.
- The malware scan unpacks every layer's regular files under generated names in a private temporary directory, so names from the image never reach the file system or scanner output. It checks that the scanner covered every file, and deletes the directory after each layer. Directory scans copy files the same way, in batches.
- Directory scans read only through the scanned directory (never following a symlink out of it), stop if the directory changes while it is scanned, and list the files Trivy does not read.

## Roadmap

- GitLab CI template
- Malware checks in rescans of pulled images

## Development

```sh
go test ./...
docker build -t scanproof:dev .
```

The PDF test runs only where `typst` is installed, such as inside the image.

## License

Apache License 2.0. See [LICENSE](LICENSE).
