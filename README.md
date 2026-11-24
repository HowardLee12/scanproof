# ScanProof

ScanProof scans a container image in CI and keeps the result as evidence you can hand to an auditor.

It runs [Trivy](https://github.com/aquasecurity/trivy) for vulnerabilities and embedded secrets, applies a policy and your approved exceptions, and writes:

| File | For |
|---|---|
| `results.json` | Every finding, the policy result and the CI context, in one machine-readable file |
| `summary.md` | The GitHub Actions job summary |
| `report.pdf` | A short report for auditors: verdict, image digest, change, findings, exceptions |
| `manifest.json` | SHA-256 of each file, so anyone can check later that nothing was changed |

It can also post the result to Discord or Slack.

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

## Policy

Without a policy file, ScanProof **warns** about fixable Critical vulnerabilities and about any embedded secret. Start in warn mode, look at what it finds for a couple of weeks, then switch to enforce.

```yaml
# .scanproof/policy.yaml
mode: warn            # warn | enforce
fail_on:
  severity: CRITICAL  # lowest severity that counts as a violation
  fixable_only: true  # only count vulnerabilities that have a fix
  secrets: true       # count every embedded secret
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

  --policy FILE          policy file (default: built-in policy)
  --exceptions FILE      exceptions file
  --mode warn|enforce    overrides the policy file
  --out DIR              output directory (default scanproof-out)
  --pdf=false            skip report.pdf
  --notify WHEN          violation | always | never (default violation)
  --trivy-results FILE   use an existing Trivy JSON report
  --trivy PATH           trivy binary (default trivy)
  --typst PATH           typst binary used for the PDF (default typst)
  --timeout DURATION     scan time limit (default 30m)
```

In GitHub Actions, ScanProof also appends the summary to the job page, adds a warning or error annotation, and sets the step outputs `verdict`, `report-id`, `violations`, `results` and `evidence-dir`.

## Keeping evidence

CI artifacts expire (GitHub keeps them for 90 days by default). For audits, copy the output directory to storage that cannot be changed or deleted, for example an S3 bucket with Object Lock in compliance mode, and keep it for at least the audit period plus the time the audit takes.

The PDF maps the report to SOC 2 criteria CC7.1 and CC8.1 for convenience. Your auditor decides whether the evidence is sufficient.

## Security notes

- Trivy settings files in the scanned repository (`trivy.yaml`, `.trivyignore`) and `TRIVY_*` variables that filter results are ignored. The only way to accept a finding is an exception with a reason and an expiry date. Registry login, cache and database mirror variables are still passed through.
- Imported Trivy reports (`--trivy-results`) must come from `trivy image`, and the report says that secret scanning could not be verified.
- Secret findings record the rule, file and line only. The matched text is never stored or printed.
- Values from scan results are passed to the PDF template as data, never as template code.
- The image pins Trivy by digest and verifies the Typst download by SHA-256.

## Roadmap

- Daily rescans of images running in Amazon ECS and Kubernetes
- Period summary report and a population list for audit sampling
- Malware scanning with ClamAV and YARA
- Remediation SLA tracking

## Development

```sh
go test ./...
docker build -t scanproof:dev .
```

The PDF test runs only where `typst` is installed, such as inside the image.

## License

Apache License 2.0. See [LICENSE](LICENSE).
