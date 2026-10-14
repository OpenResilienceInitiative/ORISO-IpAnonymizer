# Static, stdlib-only binary on scratch: no shell, no package manager, non-root.
# Base images are pinned by digest. 1.26.9 fixes stdlib CVE-2026-78667,
# CVE-2026-78669 (net/http) and CVE-2026-97031 (crypto/tls).
FROM --platform=${BUILDPLATFORM} golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder
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
