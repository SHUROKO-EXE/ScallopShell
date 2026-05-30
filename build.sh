#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="build"
TYPE="${CMAKE_BUILD_TYPE:-Debug}"
CMAKE_ARGS=()

usage() {
  echo "Usage: $0 [BUILD_DIR] [--with-keystone|--fetch-keystone|--install-keystone]"
}

while (($#)); do
  case "$1" in
    --with-keystone|--fetch-keystone|--install-keystone)
      CMAKE_ARGS+=("-DSCALLOP_FETCH_KEYSTONE=ON")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      BUILD_DIR="$1"
      ;;
  esac
  shift
done

# wipe only the out-of-source build dir; keep source tree clean
rm -f "$BUILD_DIR/*"
rm -rf "$BUILD_DIR/CMakeFiles"

# ensure no stale in-source cache exists
rm -f CMakeCache.txt
rm -rf CMakeFiles

# configure + build
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$TYPE" "${CMAKE_ARGS[@]}"
cmake --build "$BUILD_DIR" -j"$(nproc)"

ln -sf build/compile_commands.json compile_commands.json

echo "Binary: $BUILD_DIR/scallop"

cp ./build/scallop /usr/bin/
