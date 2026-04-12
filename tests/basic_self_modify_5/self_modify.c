#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>

/*
 * Self-modifying x86-64 program with 7 instructions and 5 patches.
 *
 * target_func computes a value using 7 instructions.
 * Each loop iteration applies one patch to the function's machine code,
 * changing its behavior for all subsequent calls.
 *
 * Patch 1: MOV EAX, 1    -> MOV EAX, 10     (change immediate operand)
 * Patch 2: ADD EAX, 3    -> SUB EAX, 3      (change operation type)
 * Patch 3: SHL EAX, 2    -> SHL EAX, 4      (change shift amount)
 * Patch 4: XOR EAX, 0x10 -> OR  EAX, 0x10   (change logic operation)
 * Patch 5: INC EAX       -> NOP; NOP         (remove instruction entirely)
 */

__attribute__((noinline))
int target_func(void) {
    int result;
    asm volatile (
        /* 7 instructions, fully spelled out as bytes for predictable layout */
        ".byte 0xb8, 0x01, 0x00, 0x00, 0x00\n" /* mov eax, 1       [+0]  */
        ".byte 0x83, 0xc0, 0x03\n"              /* add eax, 3       [+5]  */
        ".byte 0x89, 0xc1\n"                    /* mov ecx, eax     [+8]  */
        ".byte 0xc1, 0xe0, 0x02\n"              /* shl eax, 2       [+10] */
        ".byte 0x01, 0xc8\n"                    /* add eax, ecx     [+13] */
        ".byte 0x83, 0xf0, 0x10\n"              /* xor eax, 0x10    [+15] */
        ".byte 0xff, 0xc0\n"                    /* inc eax          [+18] */
        : "=a"(result)
        :
        : "ecx"
    );
    return result;
}

static void make_writable(void *addr, size_t len) {
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(getpagesize() - 1);
    mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

/* Each patch: offset from anchor, byte position within instruction, old, new */
typedef struct {
    int offset;         /* byte offset from anchor (mov eax,1) */
    int patch_pos;      /* which byte within the instruction to patch */
    uint8_t old_val;
    uint8_t new_val;
    const char *desc;
} Patch;

static const Patch patches[5] = {
    { 0,  1, 0x01, 0x0a, "MOV EAX,1   -> MOV EAX,10    (change immediate)"    },
    { 5,  1, 0xc0, 0xe8, "ADD EAX,3   -> SUB EAX,3     (change operation)"    },
    { 10, 2, 0x02, 0x04, "SHL EAX,2   -> SHL EAX,4     (change shift amount)" },
    { 15, 1, 0xf0, 0xc8, "XOR EAX,0x10-> OR  EAX,0x10  (change logic op)"     },
    { 18, 0, 0xff, 0x90, "INC EAX     -> NOP;NOP        (remove instruction)"  },
};

/* For patch 5 (INC -> NOP NOP) we also need to patch the second byte */

static void dump_func_bytes(uint8_t *anchor) {
    printf("  code: ");
    for (int i = 0; i < 20; i++)
        printf("%02x ", anchor[i]);
    printf("\n");
}

int main(void) {
    uint8_t *code = (uint8_t *)target_func;
    make_writable(code, getpagesize());

    /* Find the anchor: B8 01 00 00 00 (mov eax, 1) */
    uint8_t *anchor = NULL;
    for (int i = 0; i < 64; i++) {
        if (code[i] == 0xb8 && code[i+1] == 0x01 &&
            code[i+2] == 0x00 && code[i+3] == 0x00 && code[i+4] == 0x00) {
            anchor = &code[i];
            break;
        }
    }
    if (!anchor) {
        fprintf(stderr, "Could not find anchor bytes\n");
        return 1;
    }

    printf("=== Self-Modifying Program (5 patches) ===\n");
    printf("Anchor at offset +%ld from function start\n\n", anchor - code);

    for (int i = 0; i < 6; i++) {
        int val = target_func();
        printf("[iter %d] target_func() = %-4d", i, val);
        dump_func_bytes(anchor);

        if (i < 5) {
            const Patch *p = &patches[i];
            uint8_t *site = anchor + p->offset + p->patch_pos;
            printf("  patch %d: %s\n", i + 1, p->desc);
            *site = p->new_val;

            /* INC EAX is 2 bytes (FF C0) -> need to NOP both */
            if (i == 4)
                *(site + 1) = 0x90;

            __builtin___clear_cache((char *)anchor,
                                    (char *)anchor + 20);
        }
        printf("\n");
    }

    printf("All 5 patches applied.\n");
    return 0;
}
