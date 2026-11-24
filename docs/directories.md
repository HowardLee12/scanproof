# Scanning directories

Some software that runs in production is not inside a container image. A common case: GPU pods start a stock `python:3.12` image and run vLLM from a Python virtualenv on a shared network filesystem, with a Go worker binary in another directory of the same filesystem. Image scans never see that software.

`scanproof scan --dir` scans such a directory once per version, on a machine that has it, and keeps the result as normal evidence. The daily `scanproof rescan` then checks the directory's stored SBOM against today's vulnerability data without access to the directory, so it can run anywhere, for example on a CPU node while the filesystem is only mounted on GPU nodes.

## How it works

1. **Scan once per version.** On a machine that has the directory, `scanproof scan --dir` computes the directory's [tree digest](#the-tree-digest), scans it with Trivy, and optionally for malware. With `--store`, the evidence is uploaded like an image scan and indexed by the tree digest.
2. **List it for rescans.** Add a `dir:` line with the tree digest to the rescan [images file](#listing-the-directory-for-daily-rescans).
3. **Rescan every day.** `scanproof rescan` finds the stored SBOM by tree digest, checks it against its manifest, and scans it against today's vulnerability database. It never reads the directory itself.
4. **Scan again after every change.** Installing, upgrading or editing anything changes the tree digest. Scan the new version and replace the line.

## Scanning a directory

```sh
scanproof scan --dir --name acme-vllm --version 0.9.1 \
  --store s3://acme-scan-evidence/prod /mnt/shared/venvs/vllm
```

```
ScanProof WARN: directory acme-vllm:0.9.1 · 3 policy violations · warn mode · report SR-20261124-7F3A9C · evidence in s3://…
Rescan inventory line: dir:acme-vllm:0.9.1@sha256:22f1e2168f577b985f3d38b569d35c8d62cff86d90ad3d28119a42d88fabddc1
```

| Flag | Meaning |
|---|---|
| `--dir` | Scan the directory `PATH` instead of an image |
| `--name NAME` | Required. The name the directory is tracked by in reports and rescans, such as `acme-vllm`. Letters, digits, `.`, `_`, `-` and `/` |
| `--version VERSION` | Optional. The version of the software, such as `0.9.1`. Letters, digits, `.`, `_`, `-` and `+` |

Every other `scan` flag works as for images: `--policy`, `--exceptions`, `--mode`, `--store`, `--out`, `--pdf`, `--sbom`, `--notify`, `--timeout`, and the [malware](#malware) flags. `--platform`, `--docker-daemon` and `--trivy-results` only apply to images and are refused with `--dir`. In GitHub Actions the CI context is recorded as for images.

Trivy runs in `rootfs` mode, which finds installed packages: Python packages from their `dist-info` and `egg-info` metadata, Go binaries from their build information, Java archives, Node packages, and OS packages if the directory holds an operating system's package database. It also looks for embedded secrets. The same hardening as for images applies: Trivy settings files and `TRIVY_*` filter variables are ignored, and every severity is reported.

### Things to know

- **Read access.** The scan reads every file. A file it cannot read stops the scan with an error that names it.
- **Path.** `PATH` may be a symlink; it is resolved once and the evidence records the directory that was read. Mount the directory at the same path as on the host, so `directory.path` in the evidence is the real path.
- **Symlinks** inside the directory are never followed. They are part of the tree digest (with their target), but what they point to is not scanned. A virtualenv's `bin/python -> /usr/local/bin/python3` points into the image, which image scans cover.
- **Special files** (devices, sockets, named pipes) have no content to hash and reading them can block, so a directory that contains one is refused with an error that names it.
- **Changes during the scan.** ScanProof reads the directory before Trivy runs and again afterwards (with the malware scan, when it runs). If the tree digest differs, or a file changes while it is read, the scan stops and writes no evidence. A virtualenv that running Python processes can write to may gain `__pycache__` files at any time; mount it read-only for those pods, or precompile it with `python -m compileall`.

## In the evidence

A directory scan writes the same files as an image scan: `results.json`, `summary.md`, `report.pdf`, `sbom.cdx.json` and `manifest.json`.

- `results.json` has `"artifact_type": "directory"` and a `directory` object with `name`, `version`, `tree_digest`, `path`, and the number of files, directories, symlinks and bytes. Image scans have `"artifact_type": "container_image"`.
- `image.reference` is `dir:NAME[:VERSION]` and `image.digest` is the tree digest, so tools that only read `image` still group and index directories correctly.
- `manifest.json` records the artifact type and the tree digest, so a rescan can never use an image's SBOM for a directory or the other way round.
- The PDF is a "Directory Scan Report" with the name, version, tree digest, scanned path and contents. The job summary and the chat message also say "directory".
- In the period summary, `population.csv` has an `artifact_type` column and lists directories as `dir:NAME[:VERSION]`. Findings are tracked per `dir:NAME` across versions, never together with an image of the same name.

## The tree digest

The tree digest identifies the exact content of a directory, the way an image digest identifies an image. It is `sha256:` followed by 64 hex characters:

1. Resolve symlinks in `PATH` itself. That directory is the root.
2. List every entry below the root, without following symlinks. The root itself is not an entry.
3. Sort the entries by their path relative to the root, `/`-separated and without a leading `./`, comparing the bytes. (So `lib-a` comes before `lib/x`, because `-` is byte 0x2D and `/` is 0x2F.)
4. Compute SHA-256 over the bytes `scanproof-tree/v1` and a NUL byte, followed by one record per entry, in that order. Every field of a record is followed by a NUL byte:

   | Entry | Record |
   |---|---|
   | Regular file | `file` NUL *path* NUL *mode* NUL *size* NUL *content SHA-256* NUL |
   | Directory | `dir` NUL *path* NUL *mode* NUL |
   | Symlink | `symlink` NUL *path* NUL *target* NUL |

   - *mode* is the 12 permission bits (`st_mode & 07777`: read, write and execute for user, group and others, plus setuid, setgid and sticky) as 4 octal digits, such as `0644` or `4755`.
   - *size* is the file size in bytes, in decimal.
   - *content SHA-256* is the lowercase hex SHA-256 of the file's content.
   - *target* is the link target exactly as stored (`readlink`), not resolved.
   - Paths and targets are raw bytes; they cannot contain a NUL byte, so the encoding is unambiguous.

5. Any other kind of entry (device, socket, named pipe) is an error.

Not included: owners, groups, timestamps, extended attributes, ACLs, the root's own name and permissions, and the permission bits of symlinks (Linux ignores them). Empty directories are included. Hard links are hashed as separate files. Copying a directory with `cp -a` or `rsync -a` keeps its tree digest; changing a file, a permission, a name or a symlink changes it.

This script recomputes the digest, so anyone can check that evidence belongs to a directory:

```python
#!/usr/bin/env python3
"""Recompute a ScanProof tree digest (scanproof-tree/v1) of a directory."""
import hashlib
import os
import stat
import sys


def fail(err):
    raise err


def tree_digest(root):
    root = os.fsencode(os.path.realpath(root))
    paths = []
    # os.walk never follows symlinks unless followlinks=True.
    for dirpath, dirnames, filenames in os.walk(root, onerror=fail):
        for name in dirnames + filenames:
            paths.append(os.path.relpath(os.path.join(dirpath, name), root))
    digest = hashlib.sha256(b"scanproof-tree/v1\0")
    for rel in sorted(paths):  # bytes, so this is byte order
        full = os.path.join(root, rel)
        st = os.lstat(full)
        mode = b"%04o" % stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            record = [b"symlink", rel, os.readlink(full)]
        elif stat.S_ISDIR(st.st_mode):
            record = [b"dir", rel, mode]
        elif stat.S_ISREG(st.st_mode):
            content = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    content.update(chunk)
            record = [b"file", rel, mode, b"%d" % st.st_size, content.hexdigest().encode()]
        else:
            sys.exit(f"{rel!r} is not a file, directory or symlink")
        digest.update(b"".join(field + b"\0" for field in record))
    return "sha256:" + digest.hexdigest()


if __name__ == "__main__":
    print(tree_digest(sys.argv[1]))
```

```sh
python3 tree_digest.py /mnt/shared/venvs/vllm
```

## Malware

`--malware` works with `--dir` and keeps the guarantees of an image scan. Use the `-full` image.

```sh
scanproof scan --dir --name acme-vllm --version 0.9.1 --malware \
  --store s3://acme-scan-evidence/prod /mnt/shared/venvs/vllm
```

How it works:

- The malware scan is the second read of the directory. Each file is read once: hashed for the tree digest and, in the same pass, copied under a generated name (`f0000001`, `f0000002`, …) into a private batch directory. When a batch reaches about 1 GB or 20,000 files, ClamAV (and YARA, with `--yara-rules`) scans it, and the batch is deleted before the next one starts.
- The tree digest of the copied bytes must match the digest computed before Trivy ran, so the malware scan provably covered the same content as the vulnerability scan.
- The engines only ever see generated names, so a file name in the directory (with `: `, ` FOUND` or a newline in it) can never be mistaken for scanner output. Detections are mapped back to the real path by the generated name.
- ClamAV must report as many scanned files as were copied into each batch (it skips empty files, so those are not counted), and every file the walk found must be either copied or listed as not fully scanned. Otherwise the scan stops with an error.
- Files larger than `--malware-max-file-mb` are not copied; they are listed as not fully scanned, as are files on which ClamAV hit one of its limits. By default each one is a policy violation (see [malware.md](malware.md#files-that-were-not-fully-scanned)).
- Symlinks are never followed. Each file is opened without following a symlink and must be the same file (device and inode) with the same size as when it was listed.
- Paths in detections are relative to the scanned directory, and there is no layer. An exception names that relative path.

The trade-off is disk and time: `--malware-workdir` needs room for about 1 GB plus the largest file, and every byte is written once more. ClamAV loads its signatures once per batch, which takes several seconds each time. Scanning the files in place would avoid the copy, but then names from the directory would reach the scanners' output; hard links would avoid it too, but they do not work across filesystems or into a read-only mount.

## Kubernetes: a one-off scan Job

When the directory is on a filesystem that only some nodes mount (for example GPU nodes), run the scan as a one-off Job next to a pod that already uses the directory. Required pod affinity puts the Job on that pod's node, so it never starts a new node: if no matching pod is running, the Job stays Pending. Delete it and run it again later.

```yaml
# One scan of one version of a directory. Change the name, the version, the
# pod selector and the path for each scan.
apiVersion: batch/v1
kind: Job
metadata:
  name: scanproof-dir-acme-vllm-0-9-1
  namespace: scanproof-dirscan
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 7200
  ttlSecondsAfterFinished: 604800
  template:
    spec:
      restartPolicy: Never
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      # Schedule next to a running pod that uses the directory: that node
      # already has the shared filesystem, so no node has to scale up.
      affinity:
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: acme-vllm
              namespaces: ["inference"]
              topologyKey: kubernetes.io/hostname
      # GPU nodes are usually tainted. Tolerate the taint, but request no GPU.
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
      containers:
        - name: scan
          image: ghcr.io/howardlee12/scanproof:VERSION-full # a release with --dir
          args:
            - scan
            - --dir
            - --name=acme-vllm
            - --version=0.9.1
            - --malware
            - --malware-workdir=/work
            - --store=s3://acme-scan-evidence/prod
            - --out=/work/out
            - --notify=always
            - /mnt/shared/venvs/vllm
          env:
            - name: TRIVY_CACHE_DIR
              value: /work/trivy-cache
            - name: AWS_REGION
              value: us-east-2
          envFrom:
            # Store credentials and the optional chat webhooks, as for rescans.
            - secretRef:
                name: scanproof-store
          resources:
            requests:
              cpu: "1"
              memory: 2Gi # ClamAV keeps its signatures in memory
              ephemeral-storage: 4Gi
            limits:
              memory: 4Gi
              ephemeral-storage: 8Gi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            # Same path as on the node, so the evidence shows the real path.
            - name: target
              mountPath: /mnt/shared/venvs/vllm
              readOnly: true
            - name: work
              mountPath: /work
      volumes:
        - name: target
          hostPath:
            path: /mnt/shared/venvs/vllm
            type: Directory
        - name: work
          emptyDir: {}
```

```sh
kubectl apply -f scan-acme-vllm.yaml
kubectl -n scanproof-dirscan logs -f job/scanproof-dir-acme-vllm-0-9-1   # the last line is the rescan inventory line
```

Notes:

- The `baseline` and `restricted` Pod Security Standards do not allow `hostPath` volumes, so run the Job in a namespace that does, and keep who can create pods there to a minimum. If the pods that use the directory mount it through a PersistentVolumeClaim instead, mount the same claim read-only and drop the `hostPath`.
- With every capability dropped, root cannot bypass file permissions, so files that root does not own and that are not world-readable cannot be read and the scan stops with "permission denied". Add the `DAC_READ_SEARCH` capability in that case.
- The store credentials only need `s3:PutObject` on `scans/*` and `index/*` (see [storage.md](storage.md#4-permissions)).
- Without `--malware`, use the default image (no `-full`) and lower the memory request.

## Listing the directory for daily rescans

Add one line per deployed directory to the rescan images file:

```text
# Software deployed outside container images
dir:acme-vllm:0.9.1@sha256:22f1e2168f577b985f3d38b569d35c8d62cff86d90ad3d28119a42d88fabddc1   gpu-cluster/inference/acme-vllm
dir:example-worker:2.4.0@sha256:9ab1c3d5e7f90a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b   gpu-cluster/inference/example-worker
```

The format is `dir:NAME[:VERSION]@sha256:<tree digest>`, then optionally whitespace and a free-text location that is recorded as where the directory runs. NAME and VERSION are labels; the tree digest decides which stored scan is used. The scan prints the line ready to paste.

Keep the file in a repository, put it in the `scanproof-config` ConfigMap with the exceptions, and give the CronJob both inventories:

```sh
kubectl -n scanproof create configmap scanproof-config \
  --from-file=exceptions.yaml=.scanproof/exceptions.yaml \
  --from-file=images.txt=.scanproof/images.txt \
  --dry-run=client -o yaml | kubectl apply -f -
```

```yaml
args:
  - rescan
  - --inventory=kubernetes,file
  - --images-file=/config/images.txt
```

[deploy/kubernetes/cronjob.yaml](../deploy/kubernetes/cronjob.yaml) has these lines, commented out.

For a directory, the rescan:

- uses the newest stored scan of that tree digest whose SBOM matches its `manifest.json` (same SHA-256, same tree digest, artifact type `directory`);
- never pulls or reads anything else. If no such scan exists, the line is reported as failed with "no stored scan for this directory; run scanproof scan --dir on a host that has it", whatever `--pull-missing` says, and the rescan exits with 2;
- stores a normal scan record with trigger `rescan`, artifact type `directory` and the location from the line, and lists the directory in the run's chat message.

## Limits

- Trivy finds software through package metadata. Files with no metadata, such as shared libraries copied in by hand or model weights, are hashed into the tree digest and checked for secrets and malware, but not matched against vulnerability data.
- A rescan checks the stored SBOM, not the directory. If the directory is changed without a new scan, the rescans keep checking the old content. Keep each version in its own path (for example `/mnt/shared/venvs/vllm-0.9.1`), mount it read-only in the pods that use it, and scan every new version.
- Secrets and malware are checked when the directory is scanned, not by rescans, as for images.
