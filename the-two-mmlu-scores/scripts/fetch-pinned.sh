#!/bin/sh
# Fetches the two pinned upstream source trees into ./vendor (git-ignored):
#   vendor/upstream/apl/apl-core   the APL verifier workspace containing apl-ai-eval
#   vendor/evidentum.io/atl-core   the ATL library that apl-core declares as the
#                                  path dependency ../../../evidentum.io/atl-core,
#                                  three directory levels above apl-core
# Idempotent. Fails if a checkout does not resolve to exactly the pinned SHA.
set -eu

APL_CORE_URL="https://github.com/evidentum-io/apl-core"
APL_CORE_SHA="e46788cfde6d5da1dc6185265318c5861c876d99"
ATL_CORE_URL="https://github.com/evidentum-io/atl-core"
ATL_CORE_SHA="02f459c3b3717610ecc9e18e5d53b62fd1bb1b95"

root="$(cd "$(dirname "$0")/.." && pwd)"

fetch() {
    url="$1"; sha="$2"; rel="$3"; dir="$root/vendor/$rel"
    if [ ! -d "$dir/.git" ]; then
        mkdir -p "$dir"
        git -C "$dir" init --quiet
        git -C "$dir" remote add origin "$url"
    fi
    if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" != "$sha" ]; then
        git -C "$dir" fetch --quiet --depth 1 origin "$sha"
        git -C "$dir" checkout --quiet --detach --force "$sha"
    fi
    got="$(git -C "$dir" rev-parse HEAD)"
    if [ "$got" != "$sha" ]; then
        echo "pin mismatch for $rel: expected $sha, got $got" >&2
        exit 1
    fi
    if [ -n "$(git -C "$dir" status --porcelain)" ]; then
        echo "working tree of $rel is not clean" >&2
        exit 1
    fi
    echo "$rel @ $got"
}

fetch "$APL_CORE_URL" "$APL_CORE_SHA" upstream/apl/apl-core
fetch "$ATL_CORE_URL" "$ATL_CORE_SHA" evidentum.io/atl-core
