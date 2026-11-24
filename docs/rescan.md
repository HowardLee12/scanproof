# Rescanning running images

New vulnerabilities are published every day, so an image that passed its build-time scan can be vulnerable a week later. `scanproof rescan` finds the images that are running now, and the [directories](directories.md) you list, and checks them against today's vulnerability database. It stores the results with the build-time scans, so the [period summary](storage.md#period-summary) shows that running images were checked throughout the period.

## How it works

1. **Find running images.** ScanProof lists them from Kubernetes, Amazon ECS or a file (or several of these), and merges duplicates by digest. The file can also list directories by tree digest.
2. **Use the stored SBOM when there is one.** Every `scanproof scan --store …` saves an SBOM and indexes it by image digest. A rescan checks that SBOM against the current database, so it does not pull the image again. This matters for large images such as GPU and model-serving images.
3. **Otherwise pull the image.** Images that were never scanned with `--store` (for example third-party images) are pulled and scanned. They also get an SBOM, so the next rescan is quick. Use `--pull-missing=false` to skip them instead. A directory can never be pulled: without a stored scan it is reported as failed.
4. **Store and report.** Each image gets a normal scan record with trigger `rescan` and the places it runs. ScanProof then posts **one** chat message for the whole run, listing the images that have violations or could not be scanned.

A rescan from an SBOM finds new vulnerabilities in the packages the image contains. It does not look for secrets again. Secrets were checked when the image was first scanned, and the image has not changed since.

```sh
scanproof rescan --store s3://acme-scan-evidence/prod --inventory kubernetes
scanproof rescan --store s3://acme-scan-evidence/prod --inventory ecs --ecs-cluster prod
scanproof rescan --store s3://acme-scan-evidence/prod --inventory file --images-file images.txt
scanproof rescan --store s3://acme-scan-evidence/prod --inventory kubernetes,file --images-file images.txt
```

| Flag | Default | Meaning |
|---|---|---|
| `--store` | required | The evidence store that holds the build-time scans |
| `--inventory` | required | `kubernetes`, `ecs` or `file`, or a comma-separated list such as `kubernetes,file`; the results are merged by digest |
| `--namespace` | all | Kubernetes: limit to one namespace |
| `--ecs-cluster` | all clusters | ECS: cluster name or ARN; repeat for more |
| `--images-file` | | File: one image or directory per line (see [below](#the-images-file)); only read with `file` in `--inventory` (otherwise it is reported as a failure) |
| `--exceptions` | | Exceptions that apply to running images (see below) |
| `--policy` | built-in | Policy file |
| `--pull-missing` | `true` | Pull images that have no usable stored SBOM (never directories). With `false`, an image that was never scanned is skipped, but one whose stored scans exist and cannot be used is reported as failed |
| `--pdf` | `false` | Also write a `report.pdf` for every image and directory |
| `--notify` | `violation` | When to post the run summary: `violation`, `always`, `never` |
| `--timeout` | `30m` | Time limit per image or directory |

The exit code is 0 when every image and directory was rescanned and 2 when any of them failed, or when an inventory (or a line of the images file) could not be read. An inventory that fails does not stop the others: with `--inventory kubernetes,file`, the file is still rescanned when the Kubernetes API refuses access, and the failure is listed in the output and the chat message. Violations alone don't change the exit code: a rescan reports, it does not block anything.

### Exceptions for rescans

Build-time scans read exceptions from each repository. A rescan runs centrally, so it uses the one file given with `--exceptions`. Keep that file in a repository too, so changes to it are reviewed.

## Kubernetes

Run the rescan as a CronJob inside the cluster. It reads the pod list through the Kubernetes API with its own service account, so it needs no kubeconfig.

1. Apply the RBAC rules. They allow listing pods and nothing else:

   ```sh
   kubectl apply -f deploy/kubernetes/rbac.yaml
   ```

2. Create the secrets. Use workload identity for AWS instead of keys if your cluster supports it.

   ```sh
   kubectl -n scanproof create secret generic scanproof-store \
     --from-literal=AWS_ACCESS_KEY_ID=… \
     --from-literal=AWS_SECRET_ACCESS_KEY=… \
     --from-literal=SCANPROOF_DISCORD_WEBHOOK_URL=…

   # Only needed to pull images that have no stored SBOM:
   kubectl -n scanproof create secret generic scanproof-registry \
     --from-literal=TRIVY_USERNAME=… \
     --from-literal=TRIVY_PASSWORD=…

   kubectl -n scanproof create configmap scanproof-config \
     --from-file=exceptions.yaml=.scanproof/exceptions.yaml
   ```

   The store credentials need `s3:ListBucket` and `s3:GetObject` on `scans/*` and `index/*` (to find SBOMs), plus `s3:PutObject` on `scans/*` and `index/*`. See [storage.md](storage.md#4-permissions).

3. Edit `deploy/kubernetes/cronjob.yaml`: set the image tag, the `--store` URL and `AWS_REGION`, then apply it:

   ```sh
   kubectl apply -f deploy/kubernetes/cronjob.yaml
   kubectl -n scanproof create job --from=cronjob/scanproof-rescan scanproof-rescan-test   # run once now
   kubectl -n scanproof logs -f job/scanproof-rescan-test
   ```

The CronJob keeps away from GPU nodes. It only needs CPU, and it must not cause a GPU node to scale up. If your GPU nodes use a different label than `nvidia.com/gpu.present`, change the affinity rule. Pulled images go to the pod's ephemeral storage, so raise `ephemeral-storage` if you run images larger than about 15 GB that have no stored SBOM.

## Amazon ECS

Run the rescan as a scheduled ECS task (EventBridge Scheduler, for example `cron(0 3 * * ? *)`), using the ScanProof image with these arguments:

```json
["rescan", "--inventory=ecs", "--store=s3://acme-scan-evidence/prod", "--out=/tmp/out"]
```

The task role needs:

- `ecs:ListClusters`, `ecs:ListTasks` and `ecs:DescribeTasks`
- the store permissions above
- `ecr:GetAuthorizationToken`, `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer`, so it can pull ECR images that have no stored SBOM. Trivy uses the task role for ECR automatically.

The inventory covers the region in `AWS_REGION`. Schedule one task per region.

## The images file

For images that run outside Kubernetes and ECS, such as GPU servers that run containers directly, and for software that runs from a directory instead of an image, list them in a file:

```text
# GPU servers
cr.example.com/vllm:0.9@sha256:0f2c…          gpu-01
cr.example.com/example-worker:1.4@sha256:9ab1…

# Software deployed outside container images
dir:acme-vllm:0.9.1@sha256:22f1…              gpu-cluster/inference/acme-vllm
```

- One entry per line. Blank lines and lines starting with `#` are ignored.
- An image line is an image reference. Pin it to a digest; then the rescan can use the stored SBOM and checks exactly what is deployed.
- A directory line is `dir:NAME[:VERSION]@sha256:<tree digest>`. The digest is required: it is how the stored scan is found. `scanproof scan --dir` prints the line. See [directories.md](directories.md).
- Optionally, whitespace and a free-text location follow, recorded as where the image or directory runs. Without one, the location is "listed in" and the file's path.
- A malformed line is reported as failed, with its line number, and the other lines are still rescanned: an image reference that does not parse or starts with `-`, a digest that is not a full `sha256:` and 64 hex characters, or a malformed `dir:` line. A line that starts with `dir:` is always a directory.

To rescan both what runs in Kubernetes and the entries in the file, use `--inventory kubernetes,file`. In the CronJob, put the file in the `scanproof-config` ConfigMap; [deploy/kubernetes/cronjob.yaml](../deploy/kubernetes/cronjob.yaml) has the lines to uncomment:

```sh
kubectl -n scanproof create configmap scanproof-config \
  --from-file=exceptions.yaml=.scanproof/exceptions.yaml \
  --from-file=images.txt=.scanproof/images.txt \
  --dry-run=client -o yaml | kubectl apply -f -
```

A directory is always checked from its stored SBOM, verified against its manifest (same SHA-256, same tree digest, artifact type `directory`). If none was ever stored, the line is reported as failed with "no stored scan for this directory; run scanproof scan --dir on a host that has it", in the output and in the chat message. If stored scans exist but none can be used, the failure names the newest one and why, for example an SBOM that no longer matches its manifest. The same applies to an image with `--pull-missing=false`. Index entries that cannot be read are counted: if none of a digest's entries can be read, a directory (or an image that may not be pulled) fails with "N stored index entries for this digest could not be read".

## In the period summary

Rescans appear in `population.csv` with trigger `rescan` and their artifact type (`container_image` or `directory`), and the summary counts the days on which rescans ran. Directories are listed as `dir:NAME[:VERSION]` and tracked by name across versions, apart from images. All scans of the same image name on the same day are combined. A finding therefore stays open while any running copy still has it, and counts as fixed on the first day no scan of that image reports it, for example after a newer version replaces the old one everywhere.
