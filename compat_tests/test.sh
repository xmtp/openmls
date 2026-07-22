#!/usr/bin/env bash
set -euo pipefail

cargo test -F compat_0_7_1
cargo test -F compat_0_8_1
cargo test -F compat_0_8_1_extensions
# Fork storage-tag baseline (extensions-draft, storage_tag path).
cargo test -F fork-baseline
