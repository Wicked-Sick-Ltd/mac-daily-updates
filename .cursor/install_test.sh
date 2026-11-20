#!/usr/bin/env bash
# Regression checks for the cloud-agent installer. No network, no root.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=.cursor/install.sh
source "${root}/.cursor/install.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# bash -n syntax-checks only its first file argument.
bad="${work}/bad.sh"
printf 'this is not bash ((' >"$bad"
bash -n "${root}/daily-update.sh" "$bad"
bash -n "${root}/.cursor/install.sh"
if bash -n "$bad"; then
  fail "a syntax-invalid script was accepted by bash -n"
fi

# An already-pinned shfmt is left in place and not downloaded again.
existing="${work}/shfmt"
cat >"$existing" <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "3.14.1"
  exit 0
fi
exit 1
EOF
chmod +x "$existing"
SHFMT_DEST="$existing"
curl_calls=0
uname() { echo x86_64; }
curl() { curl_calls=$((curl_calls + 1)); return 1; }
install_shfmt
if [[ "$curl_calls" -ne 0 ]]; then
  fail "pinned shfmt was downloaded again"
fi

# Unknown architecture skips the download and still succeeds.
skipped="${work}/missing-shfmt"
rm -f "$skipped"
SHFMT_DEST="$skipped"
uname() { echo ppc64le; }
curl() { fail "unknown architecture tried to download shfmt"; }
install_shfmt
if [[ -e "$skipped" ]]; then
  fail "unknown architecture wrote a shfmt binary"
fi

# A failed download does not fail the installer and does not leave a binary.
download_dest="${work}/download-shfmt"
rm -f "$download_dest"
SHFMT_DEST="$download_dest"
uname() { echo x86_64; }
curl() { return 1; }
install_shfmt
if [[ -e "$download_dest" ]]; then
  fail "failed download left a shfmt binary"
fi

# A checksum mismatch refuses the bytes and does not fail the installer.
mismatch_dest="${work}/mismatch-shfmt"
rm -f "$mismatch_dest"
SHFMT_DEST="$mismatch_dest"
uname() { echo aarch64; }
curl() {
  local out=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-o" ]]; then
      out="$2"
      break
    fi
    shift
  done
  printf 'not-the-pinned-binary' >"$out"
}
install_shfmt
if [[ -e "$mismatch_dest" ]]; then
  fail "checksum mismatch installed a shfmt binary"
fi

# A missing shfmt does not fail the end-of-install tool report.
bindir="${work}/bin"
mkdir -p "$bindir"
printf '#!/bin/sh\n' >"${bindir}/shellcheck"
printf '#!/bin/sh\n' >"${bindir}/python3"
chmod +x "${bindir}/shellcheck" "${bindir}/python3"
report="$(PATH="${bindir}" report_tools 2>&1)"
if [[ "$report" != *"continuing without it"* ]]; then
  fail "missing shfmt did not warn and continue: ${report}"
fi

echo "install_test ok"
