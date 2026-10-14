# Static, stdlib-only binary on scratch: no shell, no package manager, non-root.
# Base images are pinned by digest (same Go toolchain as ORISO-Livekit).
FROM --platform=${BUILDPLATFORM} golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
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
