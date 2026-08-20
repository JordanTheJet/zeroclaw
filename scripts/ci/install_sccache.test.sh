#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="${root_dir}/scripts/ci/install_sccache.sh"

manifest="$(RUNNER_OS=Linux RUNNER_ARCH=X64 "$installer" --print-manifest)"
grep -Fxq "version=0.17.0" <<<"$manifest"
grep -Fxq "target=x86_64-unknown-linux-musl" <<<"$manifest"
grep -Fxq "asset=sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz" <<<"$manifest"
grep -Fxq "sha256=67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006" <<<"$manifest"
grep -Fxq "url=https://github.com/mozilla/sccache/releases/download/v0.17.0/sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz" <<<"$manifest"

if RUNNER_OS=Linux RUNNER_ARCH=ARM64 "$installer" --print-manifest >/dev/null 2>&1; then
  echo "expected Linux ARM64 to fail closed" >&2
  exit 1
fi
if RUNNER_OS=Windows RUNNER_ARCH=X64 "$installer" --print-manifest >/dev/null 2>&1; then
  echo "expected Windows to fail closed" >&2
  exit 1
fi
if "$installer" unexpected >/dev/null 2>&1; then
  echo "expected an unknown argument to fail closed" >&2
  exit 1
fi

fake_bin="$(mktemp -d)"
trap 'rm -rf "$fake_bin"' EXIT
cat >"${fake_bin}/sccache" <<'EOF'
#!/usr/bin/env bash
echo "sccache 0.17.0"
EOF
chmod +x "${fake_bin}/sccache"
installed_output="$(RUNNER_OS=Linux RUNNER_ARCH=X64 PATH="${fake_bin}:${PATH}" "$installer")"
grep -Fxq "sccache 0.17.0 is already installed" <<<"$installed_output"

echo "sccache manifest tests passed"
