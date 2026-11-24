# syntax=docker/dockerfile:1

# Trivy is pinned by digest. When changing TYPST_VERSION, update both
# checksums below from https://github.com/typst/typst/releases.
ARG TRIVY_IMAGE=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
ARG TYPST_VERSION=0.15.1

FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/HowardLee12/scanproof/internal/app.Version=${VERSION}" \
      -o /out/scanproof ./cmd/scanproof

FROM alpine:3.22 AS typst
ARG TYPST_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl xz
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64;  sum=a6d077d0a95eed5a2eba715b2dae06be954f624ccbf85758a03f389ded33118c ;; \
      arm64) arch=aarch64; sum=5aa8d74a3d906e60ea12a66ac2f37f8eef1b14cbad7182a745e393a10c23dcee ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/typst.tar.xz \
      "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${arch}-unknown-linux-musl.tar.xz"; \
    echo "${sum}  /tmp/typst.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/typst.tar.xz -C /tmp; \
    install -m 0755 "/tmp/typst-${arch}-unknown-linux-musl/typst" /usr/local/bin/typst

FROM ${TRIVY_IMAGE} AS base
# DejaVu Sans is the report's body font; DejaVu Sans Mono ships with Typst.
RUN apk add --no-cache font-dejavu
COPY --from=typst /usr/local/bin/typst /usr/local/bin/typst
COPY --from=build /out/scanproof /usr/local/bin/scanproof
ENTRYPOINT ["scanproof"]
CMD ["--help"]

# ClamAV signatures are downloaded once, on the build machine's own
# platform, and copied into every platform's image: one download per build,
# and the same signature version for amd64 and arm64.
# CLAMAV_DB=none leaves them out (CI, or when you mount your own).
FROM --platform=$BUILDPLATFORM alpine:3.22 AS clamdb
ARG CLAMAV_DB=download
RUN apk add --no-cache clamav \
 && mkdir -p /db && chown clamav:clamav /db \
 && if [ "$CLAMAV_DB" = "download" ]; then freshclam --stdout --no-warnings --datadir=/db; fi

# The "full" image adds ClamAV and YARA for --malware.
FROM base AS full
RUN apk add --no-cache clamav clamav-libunrar yara && mkdir -p /var/lib/clamav
COPY --from=clamdb --chown=clamav:clamav /db/ /var/lib/clamav/

# The default image: Trivy, Typst and ScanProof, without malware engines.
FROM base AS default
