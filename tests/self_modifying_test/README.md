# Scallop Shell Self-Modifying Code Demo

True bytecode self-modification at the same memory address. One function (`smc_main` at `0x400700`) contains 4 completely different x86-64 implementations, swapped at runtime using `mprotect()` and `memcpy()`.

## Iterations

- **Iteration 0** (41 bytes): Loop and sum → returns 45
- **Iteration 1** (65 bytes): Fibonacci(10) → returns 89
- **Iteration 2** (52 bytes): Power 2^10 → returns 1024
- **Iteration 3** (125 bytes): Complex math operations → returns 5

## Building

```bash
make
./scallop_demo
```

## How It Works

1. Each iteration is real compiled C code extracted from a linked binary
2. Bytecode is copied to the same function address using `memcpy()`
3. `mprotect()` temporarily makes the .text section writable
4. `mfence` flushes the instruction cache
5. Same address executes different code each iteration

## Why This Matters

- **Static analysis fails**: Traditional decompilers see only the initial bytecode
- **Instruction tracing wins**: Scallop Shell captures each iteration's actual execution
- **Real-world relevance**: Used in JIT compilation, malware obfuscation, code generation
