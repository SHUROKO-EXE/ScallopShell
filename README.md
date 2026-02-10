
# Scallop Shell - Debugger and Decompiler for Polymorphic code

<img width="520" height="520" alt="pixil-frame-0(2)" src="https://github.com/user-attachments/assets/499ccef4-afb0-4c02-888e-1045d65894cb" />

Alpha 1.1.0 

## Supported Platforms

Linux, macOS in development

## Motivation

GDB, pwndbg, Ghidra, IDA, are the current industry standards in reverse engineering. They are not well optimized for reverse engineering polymorphic binaries. The debuggers statically disassemble memory instead of displaying currently run instructions. They also aren't supported on Windows, and the windows debuggers are mostly GUI based. The decompilers completely break once you involve polymorphic code. 

## Usage

```
scallop [OPTIONS]


OPTIONS:
  -h,     --help              Print this help message and exit 
  -f,     --file REQUIRED     Filepath to target binary
  -a,     --arch TEXT         Target Architecture, whatever the suffix of the QEMU binary
                                 is (qemu-riscv64 -> riscv64, qemu-aarch64 -> aarch64)
  -s,     --system BOOLEAN    Is system? 
```
## Installation

Build QEMU from source, make sure the TCG Plugin flags are set. Without this, the Linux native implementation will not work. Then, go to ~/.bashrc, 
```
export QEMU_SRC_DIR= # Source directory for the custom QEMU build (only if building plugin from source!)
export SCALLOP_QEMU_BUILD= # Build path of QEMU
export SCALLOP_QEMU_PLUGIN= # Plugin path for scallop_plugin.so
```
### To compile from source 

Above instructions. Then download the capstone package. WITHOUT THIS THIS WILL NOT FUNCTION. For me in Fedora, it'll be:
```bash
sudo dnf install capstone        # Just running the precompiled binary
sudo dnf install capstone-devel  # Compiling from source
```
For the decompiler, run:
```bash
sudo dnf install llvm-devel
```
But your specific install command may vary, check the documentation for YOUR OS / Distro. 

Then, run in the main project directory:
```bash 
chmod +x ./build.sh
./build.sh
```

This will compile it using CMake and do all the linking for you. 

## Adding to path

If you want to add it to your command line, copy paste this into your .bashrc file (located in ~/)
```bash 
export PATH=$PATH:~/path/to/package
```
You can also just move it to your /usr/bin/. I don't see a downside to this. 
 
## Controls

The controls right now are not ideal. CtrlS will assign you to the CLI, CtrlA to the memory display, CtrlD the disassembly, CtrlI for the I/O display. If you want to patch the bytes in memory or code display, the display *must be selected*. This is indicated by the window being highlighted. Up and Down arrows do different things in different windows (CLI and I/O display the up arrow lets you go to the memory display, the other displays have scrolling instead). If you want to access the other tabs, you have to have the memory display selected, then press ShiftTab. Tab is not currently working. Again, sorry for any end users using this right now. The controls are bad and this will be improved. CtrlF will let you search memory in the memory display, and search for a specific file descriptor in the I/O display.  

## Live Patching

One feature of Scallop Shell is live patching in the byte displays. If you want to change any of the bytes in the display, just click on the byte you want to change. Of course, the only values you can enter are 0-9 and A-F. Once you're done patching the bytes, hit enter and it'll save. You can hit Shift+Z to undo the edits you made UNTIL you step to the next instruction. Upon stepping, the live patcher will send a request to the emulator to modify the memory you changed. This then clears the history, so undoing is no longer possible. You can still edit it again of course.

## Notepad 

You can take notes on the Notepad tab about what you're working on. Ctrl+S to save. When you open up that binary in Scallop Shell again, it'll open your old notes back up.

## Debugging

You can run "step N", with N being the amount of instructions you want to step (this can be left blank for a default of 1). the "focus" command will filter out all memory outside of the low and high argument you specify (for example, "focus 0x400000 0x500000" will only output the instructions inside that range). Hitting enter will run the last command. 

Scallop Shell shows you the instruction right before it runs. So if you want to patch anything before it runs it'll let you. 

## Breakpoints 

Break anywhere you want by putting "break 0x" , followed by the instruction to break at. 
```
break 0x400360
```

## Instruction filtering

Currently, all instructions executed outside of the binary range are ignored. This leaves things like mmap() with executable memory unhandled by Scallop Shell. This will be fixed in a later version. 

## Decompilation

Currently very experimental. It reconstructs the binary from the runtime instruction dump CSV, only with the instructions that have been run. This *DOES NOT YET* work for self modifying binaries: it preserves the first instruction that is run at a certain address, making this completely useless until it's supported. The theory is there and the implementation is planned. For now, please use standard reverse engineering workflows. Development on the decompiler is dynamic, and constant changes will occur until it is at a working stage.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

You are free to use, modify, and distribute this software.
If you offer it as a service or redistribute modified versions,
you must make the full source code available under the same license.

Commercial relicensing may be available in the future.

## Trademark

The project name and logo are trademarks of SHUROKO.EXE.
Use of the name or logo in commercial offerings requires explicit permission.
This project is not affiliated with, endorsed by, or sponsored by any company unless explicitly stated.

## No Endorsement

Use of this software does not imply endorsement by the author.

## Contributing

By contributing to this project, you agree to the Contributor License Agreement (CLA).
The CLA allows the maintainer to relicense contributions while contributors retain
copyright to their work.
