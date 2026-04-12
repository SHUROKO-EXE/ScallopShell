#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_QEMU_SRC="/home/bradley/SoftDev/qemu"
QEMU_SRC_DIR="${QEMU_SRC_DIR:-$DEFAULT_QEMU_SRC}"

if [[ ! -f "$QEMU_SRC_DIR/include/qemu/qemu-plugin.h" && -f "$DEFAULT_QEMU_SRC/include/qemu/qemu-plugin.h" ]]; then
  printf 'warning: ignoring invalid QEMU_SRC_DIR=%s and using %s\n' "$QEMU_SRC_DIR" "$DEFAULT_QEMU_SRC" >&2
  QEMU_SRC_DIR="$DEFAULT_QEMU_SRC"
fi

QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$QEMU_SRC_DIR/build}"

if [[ ! -f "$QEMU_SRC_DIR/include/qemu/qemu-plugin.h" ]]; then
  printf 'error: qemu-plugin.h not found under QEMU_SRC_DIR=%s\n' "$QEMU_SRC_DIR" >&2
  printf 'set QEMU_SRC_DIR to your QEMU checkout before running this script\n' >&2
  exit 1
fi

if [[ ! -d "$QEMU_BUILD_DIR" ]]; then
  printf 'error: QEMU build directory not found: %s\n' "$QEMU_BUILD_DIR" >&2
  printf 'set QEMU_BUILD_DIR to the QEMU build tree before running this script\n' >&2
  exit 1
fi

mkdir -p "$SCRIPT_DIR/build"
cd "$SCRIPT_DIR/build"

cmake .. \
  -DQEMU_SRC="$QEMU_SRC_DIR" \
  -DQEMU_BUILD="$QEMU_BUILD_DIR"

cmake --build .
mv librefactorscallop.so ../scallop_plugin.so
