#!/bin/bash
set -euo pipefail

SCALLOP_BUILD_ARGS=()

usage() {
	echo "Usage: $0 [--with-keystone|--fetch-keystone|--install-keystone]"
}

while (($#)); do
	case "$1" in
		--with-keystone|--fetch-keystone|--install-keystone)
			SCALLOP_BUILD_ARGS+=("--with-keystone")
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 1
			;;
	esac
	shift
done

# Install QEMU
git clone https://github.com/qemu/qemu.git

if command -v apt >/dev/null 2>&1; then
	sudo apt install -y binutils gcc ninja-build libglib2.0-dev flex bison cmake llvm-dev libzstd-dev
elif command -v dnf >/dev/null 2>&1; then
	sudo dnf install -y binutils gcc ninja-build glib2-devel flex bison cmake llvm-devel libzstd-devel
fi

cd qemu
QEMU_SRC_DIR=$PWD

mkdir build
cd build
SCALLOP_QEMU_BUILD=$PWD
../configure --enable-plugins
make
cd ../../

# Install Scallop Shell

cd ScallopShell
SCALLOP_SOURCE=$PWD

sudo ./build.sh "${SCALLOP_BUILD_ARGS[@]}"
cd qemu-plugins/
SCALLOP_QEMU_PLUGIN=$PWD/scallop_plugin.so
./build.sh
cd ../decompiler
sudo ./build.sh
