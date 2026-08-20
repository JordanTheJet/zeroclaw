#!/usr/bin/env bash
set -euo pipefail

version="0.17.0"
target="x86_64-unknown-linux-musl"
asset="sccache-v${version}-${target}.tar.gz"
sha256="67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006"
url="https://github.com/mozilla/sccache/releases/download/v${version}/${asset}"

die() {
  echo "error: $*" >&2
  exit 1
}

runner_os="${RUNNER_OS:-$(uname -s)}"
runner_arch="${RUNNER_ARCH:-$(uname -m)}"
case "$runner_os" in
  Linux*) ;;
  *) die "sccache is only configured for Blacksmith Linux runners (got $runner_os)" ;;
esac
case "$runner_arch" in
  X64|x86_64|amd64) ;;
  *) die "sccache ${version} is not pinned for architecture $runner_arch" ;;
esac

if [[ "${1:-}" == "--print-manifest" ]]; then
  printf 'version=%s\ntarget=%s\nasset=%s\nsha256=%s\nurl=%s\n' \
    "$version" "$target" "$asset" "$sha256" "$url"
  exit 0
fi
[[ $# -eq 0 ]] || die "usage: scripts/ci/install_sccache.sh [--print-manifest]"

if command -v sccache >/dev/null 2>&1 && [[ "$(sccache --version)" == "sccache ${version}" ]]; then
  echo "sccache ${version} is already installed"
  exit 0
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
archive="${tmp_dir}/${asset}"

curl --fail --location --silent --show-error \
  --connect-timeout 15 --max-time 120 --retry 3 --retry-all-errors \
  --proto '=https' --tlsv1.2 \
  "$url" -o "$archive"

actual_sha256="$(sha256sum "$archive" | awk '{ print $1 }')"
if [[ "$actual_sha256" != "$sha256" ]]; then
  die "checksum mismatch for $asset (expected $sha256, got $actual_sha256)"
fi

tar -xzf "$archive" -C "$tmp_dir"
source_binary="${tmp_dir}/sccache-v${version}-${target}/sccache"
[[ -f "$source_binary" ]] || die "sccache was not present in $asset"

install_dir="${CARGO_HOME:-${HOME}/.cargo}/bin"
mkdir -p "$install_dir"
cp "$source_binary" "${install_dir}/sccache"
chmod +x "${install_dir}/sccache"
"${install_dir}/sccache" --version
