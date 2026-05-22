# Assembler Display

Select it and type in your assembly instructions. Assembled using Keystone.

The target list is populated from the Keystone architectures and modes that the current build can open. The instrumented architecture is selected by default, but you can switch targets for cases like shellcode assembly.

Syntax options update for the selected target. X86 targets expose Intel and AT&T syntax; other supported targets use Keystone's default syntax. Endianness is shown separately and is selectable only when the selected target supports both little and big endian modes.
