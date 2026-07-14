#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$QEMU_SRC_DIR/build}"

if [[ ! -f "$QEMU_SRC_DIR/include/plugins/qemu-plugin.h" ]]; then
  printf 'error: qemu-plugin.h not found under QEMU_SRC_DIR=%s\n' "$QEMU_SRC_DIR" >&2
  printf 'set QEMU_SRC_DIR to your QEMU checkout before running this script\n' >&2
  exit 1
fi

if [[ ! -d "$QEMU_BUILD_DIR" ]]; then
  printf 'error: QEMU build directory not found: %s\n' "$QEMU_BUILD_DIR" >&2
  printf 'set QEMU_BUILD_DIR to the QEMU build tree before running this script\n' >&2
  exit 1
fi

QEMU_CONFIG_HOST="$QEMU_BUILD_DIR/config-host.h"
if [[ ! -f "$QEMU_CONFIG_HOST" ]]; then
  printf 'error: QEMU configuration header not found: %s\n' "$QEMU_CONFIG_HOST" >&2
  printf 'configure and build QEMU before building the plugin\n' >&2
  exit 1
fi

if ! grep -Eq '^#define[[:space:]]+CONFIG_CAPSTONE([[:space:]]|$)' "$QEMU_CONFIG_HOST"; then
  printf 'error: QEMU was built without Capstone support\n' >&2
  printf 'reconfigure QEMU with --enable-plugins --enable-capstone\n' >&2
  exit 1
fi

mkdir -p "$SCRIPT_DIR/build"
cd "$SCRIPT_DIR/build"

cmake .. \
  -DQEMU_SRC="$QEMU_SRC_DIR" \
  -DQEMU_BUILD="$QEMU_BUILD_DIR"

cmake --build .
cp -f librefactorscallop.so ../scallop_plugin.so
