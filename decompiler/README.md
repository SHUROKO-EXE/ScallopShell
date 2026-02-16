# ScallopShell Decompiler (Self-Modifying Code Support)

This tool rebuilds a minimal ELF memory image from a QEMU branch log and feeds
it to Ghidra for decompilation of self-modifying binaries. It detects multiple
instruction variants at the same PC and inserts a "switcher" stub so each
variant can be reached on successive executions.

## Inputs
- `/tmp/branchlog.csv`: instruction trace with columns:
  `pc, kind, branch_target, fallthrough, tb_vaddr, bytes, disas, symbol`
- `/tmp/scallop_file_info`: key=value file containing:
  `target_triple=<llvm triple>`

If `/tmp/scallop_file_info` is missing, the tool creates it from
`~/Downloads/checkpass` by inspecting the ELF header.

## Outputs
- `/tmp/scallop`: reconstructed ELF64 image used by Ghidra

## How it works
1) Parse `branchlog.csv` into a list of `instructionData`.
2) Group instructions by PC into "variants". A variant is a contiguous chunk
   of instructions following `fallthroughAddr` until the chain breaks.
3) For PCs with multiple variants, emit a switcher stub at the original PC:
   - Load counter, increment it, then branch to variant 0 or variant N.
   - On x86_64, the stub uses direct `jmp rel32` so Ghidra can follow flow.
4) Copy variant chunks into a new arena after the original image.
5) Relocate x86_64 PC-relative instructions in moved variants.
6) Emit an ELF with `.text`, `.data`, `.symtab`, `.strtab`, `.shstrtab`.

## Switcher stub behavior (x86_64)
The stub compares the original counter value and jumps directly:
- `idx == 0` -> `variant_0`
- otherwise -> `variant_last`

This is intentional to make Ghidra follow explicit control flow. The stub and
variants are labeled with ELF symbols for auto-disassembly.

## Build
Dependencies:
- Capstone
- LLVM (llvm-devel / LLVMConfig.cmake)

Build:
```
sudo ./build.sh
```

Run:
```
./build/scallop_decomp
```

## Limitations
- Relocation is currently implemented for x86_64 only.
- Short branches that go out of range after relocation are not expanded yet.
- Self-modifying writes are not mirrored into the variant arena.

## Key Files
- `src/memory.cpp`: image builder, variant grouping, relocation
- `src/decompilerAPI/switcher.cpp`: switcher stub emission
- `src/elf.cpp`: ELF writer with sections + symbols
- `src/file_info.cpp`: target triple file parsing/creation
