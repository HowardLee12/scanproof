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
| `--name NAME` | Required. The name the directory is tracked by in reports and rescans, such as `acme-vllm`. Letters, digits, `.`, `_`, `-`, and `/` between parts that each start with a letter or digit |
| `--version VERSION` | Optional. The version of the software, such as `0.9.1`. Letters, digits, `.`, `_`, `-` and `+` |

Every other `scan` flag works as for images: `--policy`, `--exceptions`, `--mode`, `--store`, `--out`, `--pdf`, `--sbom`, `--notify`, `--timeout`, and the [malware](#malware) flags. `--platform`, `--docker-daemon` and `--trivy-results` only apply to images and are refused with `--dir`. In GitHub Actions the CI context is recorded as for images.

Trivy runs in `rootfs` mode, which finds installed packages: Python packages from their `dist-info` and `egg-info` metadata, Go binaries from their build information, Java archives, Node packages, and OS packages if the directory holds an operating system's package database. It also looks for embedded secrets. The same hardening as for images applies: Trivy settings files in the working directory (`trivy.yaml`, `.trivyignore`, `trivy-secret.yaml`) and `TRIVY_*` filter variables are ignored, and every severity is reported.

For secrets, a directory scan goes further than an image scan. Trivy has built-in "allow rules" that skip paths such as `tests/`, `examples/`, Markdown files, `locale/` and `vendor/` directories, and system and language directories (`usr/share`, `usr/local/lib/python3.12`, …). An image scan keeps them, so that every deploy is not flooded with matches from operating system and language files. A directory scan passes Trivy its own secret settings (written to a private temporary directory) that switch all eleven allow rules off, because a virtualenv is exactly the kind of place they would hide. Example credentials in a package's tests can then be reported; accept them with an [exception](../README.md#exceptions) that names the file. Trivy still does not read every file; the evidence lists what it skipped (see [Limits](#limits)).

After the scan, ScanProof prints the line to add to the rescan images file. It does so only when the scan was stored with an SBOM; otherwise it says that rescans cannot check the directory. With `--store`, a directory scan whose SBOM cannot be written fails and stores nothing, because a rescan could never check it.

### Things to know

- **Read access.** The scan reads every file. A file it cannot read stops the scan with an error that names it.
- **Where output goes.** `--out`, `--malware-workdir`, the temporary directory and Trivy's cache (`TRIVY_CACHE_DIR`, or the user cache directory) must be outside the scanned directory; otherwise the scan is refused before it starts.
- **File names** must be valid UTF-8. JSON evidence cannot show other names exactly, so a directory that contains one is refused with an error that shows the name with escapes.
- **Path.** `PATH` may be a symlink; it is resolved once and the evidence records the directory that was read. Mount the directory at the same path as on the host, so `directory.path` in the evidence is the real path.
- **Symlinks** inside the directory are never followed. They are part of the tree digest (with their target), but what they point to is not scanned. A virtualenv's `bin/python -> /usr/local/bin/python3` points into the image, which image scans cover.
- **Special files** (devices, sockets, named pipes) have no content to hash and reading them can block, so a directory that contains one is refused with an error that names it.
- **Changes during the scan.** ScanProof reads the directory before Trivy runs and again afterwards (with the malware scan, when it runs). The second read must find the same entries with the same tree digest and, for every entry, the same device, inode, size, modification time and change time. These identity stamps are not part of the digest, so a copy keeps the digest, but they show a change that was put back while Trivy ran. Each file must also keep its identity and stamps while it is read, and the scanned directory itself must keep its own stamp (it is checked again right after Trivy, and in the second read). Otherwise the scan stops and writes no evidence. Where the platform has no device and inode numbers (other than Linux and macOS), file identity is checked with the operating system's own file IDs instead.
- **Who can write next to it.** The checks above catch the directory being changed, or swapped for another one and put back, while it is scanned. They assume that the directory's parent directories cannot be changed by untrusted users during the scan; mount the directory read-only, from a path that only administrators can change. ScanProof warns, and adds a caveat to `directory.coverage.caveats`, the job summary and the PDF, when a parent directory can be written by its group or by others without the sticky bit, or is owned by a user other than root and the one running the scan. A virtualenv that running Python processes can write to may gain `__pycache__` files at any time; mount it read-only for those pods, or precompile it with `python -m compileall`.
- **Time limit.** `--timeout` (default 30 minutes) applies to the whole scan. Trivy gets `--timeout` itself; everything together (both reads of the directory, Trivy, the signature update and the malware scan) stops at `--timeout` plus one minute. Set `--timeout` explicitly for large directories, especially with `--malware` on a network filesystem: on a shared network filesystem, a 62,000-file virtualenv took about 26 minutes with `--malware`, and a 95,000-file, 9.3 GB one took more than 30 minutes and needed a longer limit (90 minutes was enough). When the limit is reached, the scan stops with one line that says where it was, for example `the scan stopped at its --timeout of 30m0s during the malware scan (41,233 of 95,150 files scanned); raise --timeout`, and writes no evidence. A scan stopped by `SIGINT` or `SIGTERM` says "was cancelled" instead.
- **Progress.** A malware scan of a directory prints a line to stderr each time another tenth of the files has been scanned (a line per batch when there are few batches), with the files scanned so far and the time taken, so a slow or stuck scan shows in the logs.

## In the evidence

A directory scan writes the same files as an image scan: `results.json`, `summary.md`, `report.pdf`, `sbom.cdx.json` and `manifest.json`.

- `results.json` has `"artifact_type": "directory"` and a `directory` object with `name`, `version`, `tree_digest`, `path`, and the number of files, directories, symlinks and bytes. Image scans have `"artifact_type": "container_image"`.
- `directory.coverage` lists what Trivy did not read: `not_scanned` (paths checked for neither vulnerabilities nor secrets) and `secrets_not_checked` (files not checked for secrets), each with a file count, counts by reason and up to 50 paths. The job summary and the PDF ("Not checked" and a Coverage section) show the same.
- `image.reference` is `dir:NAME[:VERSION]` and `image.digest` is the tree digest, so tools that only read `image` still group and index directories correctly.
- `manifest.json` records the artifact type and the tree digest, so a rescan can never use an image's SBOM for a directory or the other way round.
- The PDF is a "Directory Scan Report" with the name, version, tree digest, scanned path and contents. The job summary and the chat message also say "directory".
- In the period summary, `population.csv` has an `artifact_type` column (the last one) and lists directories as `dir:NAME[:VERSION]`. Findings are tracked per `dir:NAME` across versions, never together with an image of the same name; `findings.csv` lists them under `dir:NAME` with artifact type `directory`.

## The tree digest

The tree digest identifies the exact content of a directory, the way an image digest identifies an image. It is `sha256:` followed by 64 hex characters:

1. Resolve symlinks in `PATH` itself. That directory is the root.
2. List every entry below the root, without following symlinks. The root itself is not an entry. (ScanProof also refuses names that are not valid UTF-8; the algorithm itself works on bytes.)
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
- The engines scan exactly the bytes that were hashed. Those bytes must give the same tree digest, and every entry the same identity stamps, as the read before Trivy ran. So the malware scan and the vulnerability scan saw the same directory, unless it was changed and fully restored, including its times, between the moments each file was read, which ordinary writes cannot do.
- The engines only ever see generated names, so a file name in the directory (with `: `, ` FOUND` or a newline in it) can never be mistaken for scanner output. Detections are mapped back to the real path by the generated name. A detection that names any other file is an error, never dropped. The work directory is resolved to its real path first, because ClamAV reports files under their real path.
- ClamAV must report as many scanned files as were copied into each batch (it does not count empty files). Across the whole scan, the files ClamAV counted plus the empty files plus the files over the size limit must equal the files the walk found. Otherwise the scan stops with an error.
- Files larger than `--malware-max-file-mb` are not copied; they are listed as not fully scanned, as are files on which ClamAV hit one of its limits. By default each one is a policy violation (see [malware.md](malware.md#files-that-were-not-fully-scanned)).
- Symlinks are never followed out of the directory. Every file and directory is opened through Go's `os.Root`, which refuses any path that leads outside the scanned directory. Inside it, `os.Root` does follow a symlink, so each opened file and directory must also be the same one (device and inode) with the same size and times as when it was listed; a symlink or another file swapped in fails that check.
- Paths in detections are relative to the scanned directory, and there is no layer. An exception names that relative path.

The trade-off is disk and time: `--malware-workdir` needs room for about 1 GB plus the largest file (ClamAV gets its own temporary directory in it for each batch), and every byte is written once more. ClamAV loads its signatures once per batch, which takes several seconds each time. Scanning the files in place would avoid the copy, but then names from the directory would reach the scanners' output; hard links would avoid it too, but they do not work across filesystems or into a read-only mount.

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
- `/work` (output, malware work files, Trivy's cache) is an `emptyDir`, outside the scanned directory, as it must be.
- Without `--malware`, use the default image (no `-full`) and lower the memory request.

## Listing the directory for daily rescans

Add one line per deployed directory to the rescan images file:

```text
# Software deployed outside container images
dir:acme-vllm:0.9.1@sha256:22f1e2168f577b985f3d38b569d35c8d62cff86d90ad3d28119a42d88fabddc1   gpu-cluster/inference/acme-vllm
dir:example-worker:2.4.0@sha256:9ab1c3d5e7f90a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b   gpu-cluster/inference/example-worker
```

The format is `dir:NAME[:VERSION]@sha256:<tree digest>`, then optionally whitespace and a free-text location that is recorded as where the directory runs. NAME and VERSION are labels; the tree digest decides which stored scan is used. The scan prints the line ready to paste. A line that starts with `dir:` is always a directory, so an image from a registry whose host is literally `dir` (with a port, as in `dir:5000/app`) must be listed under another name for that host, such as its fully qualified name.

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
- never pulls or reads anything else. If no scan of that tree digest was ever stored, the line is reported as failed with "no stored scan for this directory; run scanproof scan --dir on a host that has it", whatever `--pull-missing` says, and the rescan exits with 2. If stored scans exist but none can be used (an SBOM that no longer matches its manifest, a stored scan of another kind, or a Trivy failure), the failure names the newest stored scan and the reason; if the digest's index entries exist but none can be read, the failure says so;
- stores a normal scan record with trigger `rescan`, artifact type `directory` and the location from the line, and lists the directory in the run's chat message.

A malformed line, or an inventory that cannot be read (for example Kubernetes outside a cluster), is reported as failed in the output and the chat message, and everything else is still rescanned.

## Limits

- **What Trivy skips.** The rules below are those of Trivy 0.76.2, the version the ScanProof image pins, with its allow rules switched off as a directory scan does; another Trivy version may differ. The CI build checks them against the real Trivy by planting a secret in each kind of path, including one that only each switched-off allow rule would hide. `directory.coverage.modelled_for` records the modelled version; when the scan used another Trivy version (for example one on your `PATH` given with `--trivy`), ScanProof warns and adds a caveat to the coverage, the job summary and the PDF, because the lists may then be wrong. Image reports carry the same caveat in their note on what the allow rules skip. ScanProof works out the affected files from the directory listing and records them in `directory.coverage`, the job summary and the PDF:
  - Trivy never reads `.git` directories (and `.git` files) at any depth, or `dev`, `proc` and `sys` at the top of the scanned directory. Packages and secrets there are not found, for example a token in `src/<package>/.git/config` left by `pip install -e git+https://<token>@…`.
  - The secret scanner does not read files in `node_modules` or `.git` directories; `go.mod`, `go.sum`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock` and `Gemfile.lock`; files ending in `.jpg`, `.png`, `.gif`, `.doc`, `.pdf`, `.bin`, `.svg`, `.socket`, `.deb`, `.rpm`, `.zip`, `.gz`, `.gzip` or `.tar` (exactly these, so `.JPG` is read); and binary files, meaning any file with a control character other than tab, newline, form feed, carriage return, bell, backspace or escape in its first 300 bytes. Files under 10 bytes are not read either; they are too small for any secret rule and are not listed.
  - Trivy also skips a file at the top of the scanned directory whose name is the name of its secret settings file. ScanProof gives that file a new random name for every scan, so no real file can have it.
- **Image scans** keep Trivy's allow rules. Their report says which paths those rules skip: paths with `test` or `example` in them, Markdown files, `locale` and `vendor` directories, `usr/share`, `usr/include` and `usr/lib`, and the language directories of base images (`usr/local/go`, `usr/local/lib/python*`, `usr/lib/gems`, `usr/src/wordpress`, `opt/yarn-v*`), on top of the skips above.
- **Software without package metadata.** Trivy finds software through package metadata. Files with no metadata, such as shared libraries copied in by hand, are hashed into the tree digest and checked for malware, but not matched against vulnerability data. Model weights are usually binary or end in `.bin`, so they are not checked for secrets either.
- **Rescans check the stored SBOM, not the directory.** If the directory is changed without a new scan, the rescans keep checking the old content. Keep each version in its own path (for example `/mnt/shared/venvs/vllm-0.9.1`), mount it read-only in the pods that use it, and scan every new version.
- **Secrets and malware** are checked when the directory is scanned, not by rescans, as for images.
- **Exceptions** are not specific to images or directories. An exception with a `path` matches that path in any scan (a leading `/` is ignored, so `app/x` also matches `/app/x` in an image), and one without a path matches the finding everywhere.
- **Memory.** ScanProof keeps the directory listing in memory, a few hundred bytes per entry plus its path: tens of megabytes for 100,000 files.
- **Case.** On macOS and Windows, ScanProof compares paths without case when it checks that its output is outside the scanned directory, because their file systems usually ignore case.
