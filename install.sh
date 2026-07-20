#!/bin/bash
#set -euo pipefail#

#SCALLOP_BUILD_ARGS=()

#usage() {
#	echo "Usage: $0 [--with-keystone|--fetch-keystone|--install-keystone]"
#}

#while (($#)); do
#	case "$1" in
#		--with-keystone|--fetch-keystone|--install-keystone)
#			SCALLOP_BUILD_ARGS+=("--with-keystone")
#			;;
#		-h|--help)
#			usage
#			exit 0
#			;;
#		*)
#			echo "Unknown option: $1" >&2
#			usage >&2
#			exit 1
#			;;
#	esac
#	shift
#done

# Install QEMU
#git clone https://github.com/qemu/qemu.git

#if command -v apt >/dev/null 2>&1; then
#	sudo apt install -y binutils gcc ninja-build libglib2.0-dev flex bison cmake llvm-dev libzstd-dev python3-pip libcapstone-dev
#elif command -v dnf >/dev/null 2>&1; then
#	sudo dnf install -y binutils gcc ninja-build glib2-devel flex bison cmake llvm-devel libzstd-devel python3-pip capstone-devel
#fi

#cd qemu
#export QEMU_SRC_DIR=$PWD

#mkdir build
#cd build
#export QEMU_BUILD_DIR=$PWD
#export SCALLOP_QEMU_BUILD=$PWD
#../configure --enable-plugins --enable-capstone

#if [[ ! -f config-host.h ]] || ! grep -Eq '^#define[[:space:]]+CONFIG_CAPSTONE([[:space:]]|$)' config-host.h; then
#	echo "error: QEMU configured without Capstone support" >&2
#	echo "install the Capstone development package and rerun the installer" >&2
#	exit 1
#fi

#make
#cd ../../

# Install Scallop Shell

#cd ScallopShell
export SCALLOP_SOURCE=$PWD

sudo ./build.sh "${SCALLOP_BUILD_ARGS[@]}"
cd qemu-plugins/
export SCALLOP_QEMU_PLUGIN=$PWD/scallop_plugin.so
./build.sh
cd ../decompiler
sudo ./build.sh

# Default the QEMU paths to the bundled tree if the QEMU build section above
# didn't set them (e.g. because QEMU was already built).
QEMU_SRC_DIR="${QEMU_SRC_DIR:-$SCALLOP_SOURCE/qemu}"
QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$QEMU_SRC_DIR/build}"
SCALLOP_QEMU_BUILD="${SCALLOP_QEMU_BUILD:-$QEMU_BUILD_DIR}"

SCALLOP_ENV_FILE="$SCALLOP_SOURCE/scallop-env.sh"
{
	printf 'export QEMU_SRC_DIR=%q\n' "$QEMU_SRC_DIR"
	printf 'export QEMU_BUILD_DIR=%q\n' "$QEMU_BUILD_DIR"
	printf 'export SCALLOP_QEMU_BUILD=%q\n' "$SCALLOP_QEMU_BUILD"
	printf 'export SCALLOP_QEMU_PLUGIN=%q\n' "$SCALLOP_QEMU_PLUGIN"
	printf 'export SCALLOP_SOURCE=%q\n' "$SCALLOP_SOURCE"
} > "$SCALLOP_ENV_FILE"

sudo install -m 0644 "$SCALLOP_ENV_FILE" /etc/profile.d/scallop.sh

# Source the env file from ~/.bashrc so interactive shells pick it up
BASHRC="$HOME/.bashrc"
if [[ -w "$BASHRC" || ! -e "$BASHRC" ]] && ! grep -Fq "scallop-env.sh" "$BASHRC" 2>/dev/null; then
	{
		printf '\n# ScallopShell environment (added by ScallopShell install.sh)\n'
		printf '[ -f %q ] && . %q\n' "$SCALLOP_ENV_FILE" "$SCALLOP_ENV_FILE"
	} >> "$BASHRC"
	echo "Added scallop-env.sh to $BASHRC"
fi

echo "Scallop environment installed at /etc/profile.d/scallop.sh"
echo "Open a new shell or run: source '$SCALLOP_ENV_FILE'"
