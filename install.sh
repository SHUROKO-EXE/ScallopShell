#!/bin/bash

mkdir scallop_working_dir
cd scallop_working_dir

# Install QEMU
git clone https://github.com/qemu/qemu.git

cd qemu
QEMU_SRC_DIR=$PWD

mkdir build
cd build
SCALLOP_QEMU_BUILD=$PWD
../configure
make

# Install Scallop Shell

git clone https://github.com/SHUROKO-EXE/ScallopShell.git

cd ScallopShell
SCALLOP_SOURCE=$PWD

sudo ./build.sh
cd qemu-plugins/
SCALLOP_QEMU_PLUGIN=$PWD/scallop_plugin.so
./build.sh
cd ../decompiler
sudo ./build.sh
