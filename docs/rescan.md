# Rescanning running images

New vulnerabilities are published every day, so an image that passed its build-time scan can be vulnerable a week later. `scanproof rescan` finds the images that are running now and checks them against today's vulnerability database. It stores the results with the build-time scans, so the [period summary](storage.md#period-summary) shows that running images were checked throughout the period.

## How it works

1. **Find running images.** ScanProof lists them from Kubernetes, Amazon ECS or a file, and merges duplicates by digest.
2. **Use the stored SBOM when there is one.** Every `scanproof scan --store …` saves an SBOM and indexes it by image digest. A rescan checks that SBOM against the current database, so it does not pull the image again. This matters for large images such as GPU and model-serving images.
3. **Otherwise pull the image.** Images that were never scanned with `--store` (for example third-party images) are pulled and scanned. They also get an SBOM, so the next rescan is quick. Use `--pull-missing=false` to skip them instead.
4. **Store and report.** Each image gets a normal scan record with trigger `rescan` and the places it runs. ScanProof then posts **one** chat message for the whole run, listing the images that have violations or could not be scanned.

A rescan from an SBOM finds new vulnerabilities in the packages the image contains. It does not look for secrets again. Secrets were checked when the image was first scanned, and the image has not changed since.

```sh
scanproof rescan --store s3://acme-scan-evidence/prod --inventory kubernetes
scanproof rescan --store s3://acme-scan-evidence/prod --inventory ecs --ecs-cluster prod
scanproof rescan --store s3://acme-scan-evidence/prod --inventory file --images-file images.txt
```

| Flag | Default | Meaning |
|---|---|---|
| `--store` | required | The evidence store that holds the build-time scans |
| `--inventory` | required | `kubernetes`, `ecs` or `file` |
| `--namespace` | all | Kubernetes: limit to one namespace |
| `--ecs-cluster` | all clusters | ECS: cluster name or ARN; repeat for more |
| `--images-file` | | File: one image reference per line; `#` starts a comment |
| `--exceptions` | | Exceptions that apply to running images (see below) |
| `--policy` | built-in | Policy file |
| `--pull-missing` | `true` | Pull images that have no stored SBOM |
| `--pdf` | `false` | Also write a `report.pdf` for every image |
| `--notify` | `violation` | When to post the run summary: `violation`, `always`, `never` |
| `--timeout` | `30m` | Time limit per image |

The exit code is 0 when every image was rescanned and 2 when any image failed. Violations alone don't change the exit code: a rescan reports, it does not block anything.

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

## Other hosts

For images that run outside Kubernetes and ECS, such as GPU servers that run containers directly, list them in a file:

```text
# GPU servers
cr.example.com/vllm:0.9@sha256:0f2c…
cr.example.com/ocr-worker:1.4@sha256:9ab1…
```

Pin each line to a digest. Then the rescan can use the stored SBOM and checks exactly what is deployed.

## In the period summary

Rescans appear in `population.csv` with trigger `rescan`, and the summary counts the days on which rescans ran. All scans of the same image name on the same day are combined. A finding therefore stays open while any running copy still has it, and counts as fixed on the first day no scan of that image reports it, for example after a newer version replaces the old one everywhere.
