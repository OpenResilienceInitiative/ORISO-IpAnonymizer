# Static, stdlib-only binary on scratch: no shell, no package manager, non-root.
# The pinned compiler supplies the standard library shipped in the binary.
# Go 1.26.11 fixes CVE-2026-97054, which the image gate reports on 1.26.10.
FROM --platform=${BUILDPLATFORM} golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS builder
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ip-anonymizer .

FROM scratch
COPY --from=builder /out/ip-anonymizer /ip-anonymizer
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ip-anonymizer"]
