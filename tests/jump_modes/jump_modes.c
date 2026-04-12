#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Test binary for decompiler experiments around jump reconstruction.
 *
 * relative_jump_demo:
 *   Uses normal x86-64 conditional/unconditional branches. These encode as
 *   PC-relative jumps, which most decompilers recover into structured control
 *   flow.
 *
 * absolute_jump_demo:
 *   Forces execution through absolute code addresses by materializing label
 *   addresses in a jump table and using GNU C's computed goto. On x86-64 this
 *   becomes an indirect jump through a register/memory operand rather than a
 *   direct relative branch.
 *
 * Build suggestion:
 *   gcc -O0 -fno-pie -no-pie -g -o jump_modes jump_modes.c
 */

__attribute__((noinline))
int relative_jump_demo(int x) {
    int acc = 0;

    if (x < -3) {
        acc = x - 11;
        goto done;
    }

    if ((x & 1) == 0) {
        acc = x * 4;
    } else {
        acc = x + 9;
    }

    if (x == 7) {
        acc ^= 0x55;
    } else {
        acc -= 3;
    }

done:
    return acc;
}

__attribute__((noinline))
int absolute_jump_demo(int x) {
    static void *dispatch[] = {
        &&neg_path,
        &&zero_path,
        &&even_path,
        &&odd_path
    };

    int acc = 0;
    uintptr_t target;

    if (x < 0) {
        target = (uintptr_t)dispatch[0];
    } else if (x == 0) {
        target = (uintptr_t)dispatch[1];
    } else if ((x & 1) == 0) {
        target = (uintptr_t)dispatch[2];
    } else {
        target = (uintptr_t)dispatch[3];
    }

    goto *(void *)target;

neg_path:
    acc = -x;
    goto finish;

zero_path:
    acc = 100;
    goto finish;

even_path:
    acc = x * 6;
    goto finish;

odd_path:
    acc = x * 6 + 1;

finish:
    return acc + 5;
}

int main(void) {
    int samples[] = { -5, 0, 2, 7 };
    size_t count = sizeof(samples) / sizeof(samples[0]);

    puts("== relative jumps ==");
    for (size_t i = 0; i < count; ++i) {
        int x = samples[i];
        printf("relative_jump_demo(%d) = %d\n", x, relative_jump_demo(x));
    }

    puts("\n== absolute indirect jumps ==");
    for (size_t i = 0; i < count; ++i) {
        int x = samples[i];
        printf("absolute_jump_demo(%d) = %d\n", x, absolute_jump_demo(x));
    }

    return EXIT_SUCCESS;
}
