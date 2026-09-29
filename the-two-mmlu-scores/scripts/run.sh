#!/bin/sh
# Reproduces the recorded run: fetches the pinned upstream sources, runs the
# upstream apl-ai-eval test suite at the pinned commit, then runs this crate's
# byte-for-byte output checks, fmt and clippy. The raw output is written to logs/run.log.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mkdir -p logs

{
    echo "== toolchain"
    rustc --version
    cargo --version
    echo "== pinned sources"
    sh scripts/fetch-pinned.sh
    echo "== upstream: cargo test -p apl-ai-eval (in vendor/upstream/apl/apl-core)"
    (cd vendor/upstream/apl/apl-core && cargo test --locked -p apl-ai-eval 2>&1)
    echo "== this crate: cargo test --locked"
    RUSTFLAGS="-D warnings" cargo test --locked 2>&1
    echo "== this crate: cargo fmt --check"
    cargo fmt --check 2>&1 && echo "fmt: ok"
    echo "== this crate: cargo clippy --all-targets --locked -- -D warnings"
    RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked -- -D warnings 2>&1
} | tee logs/run.log
