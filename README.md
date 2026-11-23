# ORISO IP Anonymizer

Caritas promises users of ORISO anonymity. This service makes sure no ORISO
backend ever sees a real client IP address.

ingress-nginx calls it as an `auth-request` before forwarding every request
(`global-auth-url`). It maps the client to a random, session-scoped UUID and
returns it as `X-Anon-Id`; nginx then replaces `X-Real-IP` and `X-Forwarded-For`
with that UUID. The signed cookie carries a random session token and a fixed
30-minute expiry. Replicas derive the same ID from the token and a shared key.
The service stores no session map and logs no IP addresses.

| Endpoint | Purpose |
|---|---|
| `GET /auth` | auth-request target: returns `200` with `X-Anon-Id`, sets the `anon-session` cookie (`HttpOnly; Secure; SameSite=Strict`) on a new session |
| `GET /healthz` | liveness/readiness probe |

Listens on `:8080`. Standard library only, no dependencies.

## Deployment

Deployed by the ORISO Helm chart
([OpenResilienceInitiative/ORISO-Helm](https://github.com/OpenResilienceInitiative/ORISO-Helm),
`ipAnonymizer.*` values, `templates/ip-anonymizer/`). It is fail-closed: if the
service is unavailable, nginx rejects requests instead of passing real IPs.

Set `ANON_SESSION_KEY` from a Kubernetes Secret before deploying this version.
Use a randomly generated 32-byte key encoded as standard base64. Inject the
same value into every replica and keep it across ordinary restarts. The service
requires a valid key to start. Keep the Helm replica guard until the chart
provides the shared key and the ready image has been verified.

A legacy cookie is replaced on first use. Rotating the shared key also starts
new anonymous sessions. Apply the same key change to all replicas together.

## Releases

Images are published to `ghcr.io/openresilienceinitiative/ip-anonymizer:<version>`.
The version follows the ORISO platform release in which the image changed, like
every other ORISO image.

To release, push a branch `release/ip-anonymizer-<version>` (for example
`release/ip-anonymizer-2.0.12`). The workflow validates the source, scans the
image with Trivy (fixable CRITICAL/HIGH findings stop the release), publishes it
for `linux/amd64` and `linux/arm64` with SBOM and provenance, then creates the
tag `v<version>` and the GitHub release.

Pull requests run gofmt, `go vet`, `go build`, `go test` and the same image scan.

Moved from ORISO-Helm (introduced in ORISO-Helm#375).
