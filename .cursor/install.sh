#!/usr/bin/env bash
# Cursor Cloud Agent bootstrap for mac-daily-updates.
# Installs static validation tools only. Idempotent and non-interactive.
# Does not run daily-update.sh, Homebrew, softwareupdate, or mas.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# No API credentials are required for static validation.
# If a later check needs a secret, read that named environment variable,
# warn when it is unset, and continue. Never fail install for a missing
# secret, and never print a secret value.

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

run_root env DEBIAN_FRONTEND=noninteractive apt-get update
run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  python3 \
  shellcheck

install_shfmt() {
  local version="3.14.1"
  local dest="/usr/local/bin/shfmt"
  local uname_m shfmt_arch sum url tmp

  if [[ -x "$dest" ]] && "$dest" --version 2>/dev/null | grep -q '3\.14\.1'; then
    return 0
  fi

  uname_m="$(uname -m)"
  case "$uname_m" in
    x86_64)
      shfmt_arch="amd64"
      sum="76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf"
      ;;
    aarch64 | arm64)
      shfmt_arch="arm64"
      sum="5f2db09dae91fca848f7adbdd014632e921a383863a2ad7e0450ad3aba0c6489"
      ;;
    *)
      echo "warning: shfmt has no pinned binary for ${uname_m}; skipping shfmt" >&2
      return 0
      ;;
  esac

  tmp="$(mktemp)"
  url="https://github.com/mvdan/sh/releases/download/v${version}/shfmt_v${version}_linux_${shfmt_arch}"
  if ! curl -fsSL "$url" -o "$tmp"; then
    rm -f "$tmp"
    echo "error: failed to download shfmt ${version}" >&2
    return 1
  fi
  if ! echo "${sum}  ${tmp}" | sha256sum -c -; then
    rm -f "$tmp"
    echo "error: shfmt checksum mismatch" >&2
    return 1
  fi
  run_root install -m 0755 "$tmp" "$dest"
  rm -f "$tmp"
}

install_bats_if_tests_exist() {
  local repo_root found
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  found="$(find "$repo_root" -type f -name '*.bats' -not -path '*/.git/*' -print -quit)"
  if [[ -z "$found" ]]; then
    echo "no bats tests; skipping bats"
    return 0
  fi
  run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bats
}

install_shfmt
install_bats_if_tests_exist
python3 -c 'import plistlib'

echo "install ok"
command -v shellcheck
command -v shfmt
command -v python3
