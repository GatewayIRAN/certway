#!/bin/bash
set -e
cd "$(dirname "$0")"
cargo build --manifest-path crates/cli/Cargo.toml --release
echo "Build completed successfully"
