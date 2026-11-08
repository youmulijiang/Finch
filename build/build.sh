#!/usr/bin/env bash
# Finch one-key build script (bash).
#
# Usage:
#   ./build/build.sh                # build for the current platform
#   ./build/build.sh windows        # x86_64-pc-windows-msvc
#   ./build/build.sh linux          # x86_64-unknown-linux-gnu
#   ./build/build.sh macos          # aarch64-apple-darwin (Apple Silicon)
#   ./build/build.sh macos-intel    # x86_64-apple-darwin
#   ./build/build.sh all            # every supported target
#   ./build/build.sh -h             # print help
#
# The output binary is copied to <repo>/bin/finch-<target>.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BUILD_DIR="$ROOT/bin"
mkdir -p "$BUILD_DIR"

print_help() {
    cat << 'EOF'
Finch one-key build script.

Usage: ./build/build.sh [platform]

Platforms:
  current      Build for the platform the script runs on (default)
  windows      x86_64-pc-windows-msvc
  linux        x86_64-unknown-linux-gnu
  macos        aarch64-apple-darwin (Apple Silicon)
  macos-intel  x86_64-apple-darwin
  all          Build every supported target

Options:
  -h, --help   Print this help and exit

Output:
  Binaries are copied to <repo>/bin/finch-<target>.

Cross builds need the corresponding toolchain/linker installed locally;
full multi-platform artifacts are also built by CI on release tags
(.github/workflows/release.yml).
EOF
}

case "${1:-current}" in
    -h|--help|help) print_help; exit 0 ;;
esac

current_target() {
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*|Windows*) echo "x86_64-pc-windows-msvc" ;;
        Darwin)
            if [[ "$(uname -m)" == "arm64" ]]; then
                echo "aarch64-apple-darwin"
            else
                echo "x86_64-apple-darwin"
            fi
            ;;
        *) echo "x86_64-unknown-linux-gnu" ;;
    esac
}

build_target() {
    local target="$1"
    echo "==> Building $target ..." >&2

    # Install the toolchain if missing.
    if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
        echo "    installing rustup target $target" >&2
        rustup target add "$target"
    fi

    cargo build --release --locked --target "$target"

    local bin="$ROOT/target/$target/release/finch"
    [[ -f "$bin.exe" ]] && bin="$bin.exe"

    local dest="$BUILD_DIR/finch-$target"
    cp -f "$bin" "$dest"
    echo "    -> $dest" >&2
}

case "${1:-current}" in
    current) build_target "$(current_target)" ;;
    all)     build_target "x86_64-pc-windows-msvc"
             build_target "x86_64-unknown-linux-gnu"
             build_target "aarch64-apple-darwin"
             build_target "x86_64-apple-darwin" ;;
    windows) build_target "x86_64-pc-windows-msvc" ;;
    linux)   build_target "x86_64-unknown-linux-gnu" ;;
    macos)   build_target "aarch64-apple-darwin" ;;
    macos-intel) build_target "x86_64-apple-darwin" ;;
    *) echo "unknown platform '$1' (see -h)" >&2; exit 1 ;;
esac

echo
echo "Done. Artifacts in $BUILD_DIR:" >&2
ls -lh "$BUILD_DIR" >&2
