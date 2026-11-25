#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_line() {
  grep -Fq -- "$2" "$1" || fail "$1 must contain $2"
}

line_number() {
  grep -nF -- "$2" "$1" | cut -d: -f1
}

action=.github/actions/docker-build-push/action.yml
pr=.github/workflows/ci-pull-request.yml
main=.github/workflows/ci-main.yml
release=.github/workflows/release-image.yml
for workflow in "$pr" "$main" "$release"; do
  [[ "$(grep -Fc 'uses: ./.github/actions/docker-build-push' "$workflow")" == 1 ]] ||
    fail "$workflow must use the same OCI action once"
  if grep -Eq 'load: true|docker/build-push-action|aquasecurity/trivy-action' "$workflow"; then
    fail "$workflow must use its shared archive instead of a separate scan or publish build"
  fi
done
require_line "$pr" 'push_to_ghcr: false'
if grep -Eq 'packages: write|attestations: write|id-token: write|github_token:|push_to_ghcr: true|actions/attest|docker/login-action' "$pr"; then
  fail 'Pull request validation must not have publishing credentials or operations'
fi
require_line "$main" 'push_to_ghcr: true'
require_line "$release" 'push_to_ghcr: true'
require_line "$release" 'already exists. Choose a new version.'
require_line "$release" 'release_tag: ${{ env.IMAGE }}'
require_line "$release" 'release_version: ${{ env.VERSION }}'
require_line "$action" 'already exists and will be overwritten by this release rerun.'
require_line "$action" 'platforms: linux/amd64,linux/arm64'
require_line "$action" 'push: false'
require_line "$action" 'outputs: type=oci,'
require_line "$action" 'EXPECTED_ARCHIVE_SHA256: ${{ steps.scan.outputs.archive_sha256 }}'
[[ "$(grep -Fc 'docker/build-push-action' "$action")" == 1 ]] ||
  fail 'The same archive must be scanned and published without rebuilding'
for step in 'Login to GHCR' 'Publish the scanned archive without rebuilding'; do
  grep -A 3 -F -- "- name: $step" "$action" |
    grep -Fq "inputs.push_to_ghcr == 'true'" || fail "$step must be skipped in PRs"
done

scan_line=$(line_number "$action" 'scan-image-archive.sh')
login_line=$(line_number "$action" 'docker/login-action')
publish_line=$(line_number "$action" 'publish-image-archive.sh')
((scan_line < login_line && login_line < publish_line)) ||
  fail 'The archive must pass the scan before login or upload'

for workflow in "$main" "$release"; do
  require_line "$workflow" 'subject-digest: ${{ steps.image.outputs.digest }}'
done
guard_line=$(line_number "$release" 'git ls-remote')
build_line=$(line_number "$release" 'uses: ./.github/actions/docker-build-push')
attest_line=$(line_number "$release" 'subject-digest:')
tag_line=$(line_number "$release" 'git tag -a')
release_line=$(line_number "$release" 'Create GitHub Release')
((guard_line < build_line && build_line < attest_line && attest_line < tag_line && tag_line < release_line)) ||
  fail 'The release must guard the Git tag before building and attest before releasing'
printf '%s\n' 'Shared branch, release and no-push PR workflow contract passed.'

scratch=$(mktemp -d "${TMPDIR:-/tmp}/ip-anonymizer-archive-test.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
export TEST_INDEX="$scratch/index.json" TEST_SCANS="$scratch/scans" TEST_UPLOAD="$scratch/upload"
export GITHUB_OUTPUT="$scratch/receipt" IMAGE_TAGS=example.invalid/ip-anonymizer:fixture
export TEST_FAIL_PLATFORM='' TEST_WRONG_UPLOAD_DIGEST=''
archive="$scratch/image.tar"
platforms=linux/amd64,linux/arm64
printf '%s' 'synthetic archive' > "$archive"
cat > "$TEST_INDEX" <<'JSON'
{"manifests": [
  {
    "platform": {"os": "linux", "architecture": "amd64"},
    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000001"
  },
  {
    "platform": {"os": "linux", "architecture": "arm64"},
    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000002"
  }
]}
JSON
checksum=$(sha256sum "$TEST_INDEX")
export TEST_INDEX_DIGEST="sha256:${checksum%% *}"

cat > "$scratch/skopeo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  inspect)
    [[ "$2" == --raw && "$3" == oci-archive:* ]]
    cat "$TEST_INDEX"
    ;;
  manifest-digest)
    checksum=$(sha256sum "$2")
    printf 'sha256:%s\n' "${checksum%% *}"
    ;;
  --override-os)
    [[ "$2" == linux && "$3" == --override-arch && "$5" == copy &&
       "$6" == --preserve-digests && "$7" == --digestfile ]]
    case "$4" in amd64) number=1 ;; arm64) number=2 ;; *) exit 2 ;; esac
    printf 'sha256:%064d\n' "$number" > "$8"
    ;;
  copy)
    [[ "$2" == --all && "$3" == --preserve-digests && "$4" == --authfile &&
       "$6" == --digestfile && "$8" == oci-archive:* && "$9" == docker://example.invalid/* ]]
    printf '%s\n' "$9" >> "$TEST_UPLOAD"
    printf '%s\n' "${TEST_WRONG_UPLOAD_DIGEST:-$TEST_INDEX_DIGEST}" > "$7"
    ;;
  *) exit 2 ;;
esac
SH
cat > "$scratch/trivy" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == image && "$2" == --input && "$4" == --platform &&
   "${*:6}" == '--format table --exit-code 1 --ignore-unfixed --vuln-type os,library --severity CRITICAL,HIGH' ]]
printf '%s\n' "$5" >> "$TEST_SCANS"
[[ "$5" != "$TEST_FAIL_PLATFORM" ]]
SH
chmod 700 "$scratch/skopeo" "$scratch/trivy"
export PATH="$scratch:$PATH"

scan() {
  bash scripts/ci/scan-image-archive.sh "$archive" "$platforms" "$TEST_INDEX_DIGEST"
}

publish() {
  bash scripts/ci/publish-image-archive.sh "$archive" "$TEST_INDEX_DIGEST" "$1"
}

scan
[[ "$(cat "$TEST_SCANS")" == $'linux/amd64\nlinux/arm64' ]] || fail 'Both platforms must be scanned'
[[ ! -e "$TEST_UPLOAD" ]] || fail 'The scan must not upload to a registry'
receipt=$(sed -n 's/^archive_sha256=//p' "$GITHUB_OUTPUT")
publish "$receipt"
require_line "$GITHUB_OUTPUT" "digest=$TEST_INDEX_DIGEST"
require_line "$TEST_UPLOAD" "docker://$IMAGE_TAGS"

rm "$GITHUB_OUTPUT" "$TEST_UPLOAD"
if TEST_FAIL_PLATFORM=linux/arm64 scan > "$scratch/scan.log"; then fail 'A failed platform must stop the scan'; fi
[[ ! -e "$GITHUB_OUTPUT" && ! -e "$TEST_UPLOAD" ]] || fail 'A failed scan must produce no publish receipt or upload'

if TEST_WRONG_UPLOAD_DIGEST=sha256:wrong publish "$receipt" 2> "$scratch/publish.log"; then
  fail 'A different uploaded digest must be rejected'
fi
require_line "$scratch/publish.log" 'Published image digest does not match the scanned build.'
[[ ! -e "$GITHUB_OUTPUT" ]] || fail 'A wrong uploaded digest must produce no successful publication receipt'
rm "$TEST_UPLOAD"
printf '%s' 'changed archive' > "$archive"
if publish "$receipt" 2> "$scratch/publish.log"; then fail 'A modified archive must not be published'; fi
require_line "$scratch/publish.log" 'The archive to publish differs from the scanned archive.'
[[ ! -e "$GITHUB_OUTPUT" && ! -e "$TEST_UPLOAD" ]] || fail 'A changed archive must be rejected before upload'
printf '%s\n' 'OCI archive scan and publication failure contracts passed.'
