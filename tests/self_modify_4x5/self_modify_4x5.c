#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum {
    SLOT_LEN = 6,
    SLOT_COUNT = 4,
    PATCH_ROUNDS = 5,
};

typedef struct {
    uint8_t bytes[SLOT_LEN];
    const char *desc;
} Variant;

static const Variant slot1_variants[PATCH_ROUNDS + 1] = {
    {{0x83, 0xc0, 0x05, 0x90, 0x90, 0x90}, "add eax, 5"},
    {{0x83, 0xe8, 0x05, 0x90, 0x90, 0x90}, "sub eax, 5"},
    {{0x83, 0xf0, 0x05, 0x90, 0x90, 0x90}, "xor eax, 5"},
    {{0x83, 0xc8, 0x05, 0x90, 0x90, 0x90}, "or eax, 5"},
    {{0x83, 0xe0, 0x05, 0x90, 0x90, 0x90}, "and eax, 5"},
    {{0x6b, 0xc0, 0x03, 0x90, 0x90, 0x90}, "imul eax, eax, 3"},
};

static const Variant slot2_variants[PATCH_ROUNDS + 1] = {
    {{0x83, 0xc1, 0x03, 0x90, 0x90, 0x90}, "add ecx, 3"},
    {{0x83, 0xe9, 0x03, 0x90, 0x90, 0x90}, "sub ecx, 3"},
    {{0x83, 0xf1, 0x03, 0x90, 0x90, 0x90}, "xor ecx, 3"},
    {{0x83, 0xc9, 0x03, 0x90, 0x90, 0x90}, "or ecx, 3"},
    {{0x83, 0xe1, 0x03, 0x90, 0x90, 0x90}, "and ecx, 3"},
    {{0x8d, 0x49, 0x03, 0x90, 0x90, 0x90}, "lea ecx, [rcx + 3]"},
};

static const Variant slot3_variants[PATCH_ROUNDS + 1] = {
    {{0xc1, 0xe2, 0x01, 0x90, 0x90, 0x90}, "shl edx, 1"},
    {{0xc1, 0xea, 0x01, 0x90, 0x90, 0x90}, "shr edx, 1"},
    {{0xd1, 0xc2, 0x90, 0x90, 0x90, 0x90}, "rol edx, 1"},
    {{0xd1, 0xca, 0x90, 0x90, 0x90, 0x90}, "ror edx, 1"},
    {{0xff, 0xc2, 0x90, 0x90, 0x90, 0x90}, "inc edx"},
    {{0xff, 0xca, 0x90, 0x90, 0x90, 0x90}, "dec edx"},
};

static const Variant slot4_variants[PATCH_ROUNDS + 1] = {
    {{0x83, 0xc6, 0x04, 0x90, 0x90, 0x90}, "add esi, 4"},
    {{0x83, 0xee, 0x04, 0x90, 0x90, 0x90}, "sub esi, 4"},
    {{0x83, 0xf6, 0x04, 0x90, 0x90, 0x90}, "xor esi, 4"},
    {{0x83, 0xce, 0x04, 0x90, 0x90, 0x90}, "or esi, 4"},
    {{0x83, 0xe6, 0x0f, 0x90, 0x90, 0x90}, "and esi, 0xf"},
    {{0x8d, 0x76, 0x04, 0x90, 0x90, 0x90}, "lea esi, [rsi + 4]"},
};

static const Variant *const all_variants[SLOT_COUNT] = {
    slot1_variants,
    slot2_variants,
    slot3_variants,
    slot4_variants,
};

__attribute__((noinline))
int target_func(void) {
    int result;
    asm volatile(
        ".byte 0x31, 0xc0\n"                          /* xor eax, eax */
        ".byte 0xb9, 0x0a, 0x00, 0x00, 0x00\n"        /* mov ecx, 10  */
        ".byte 0xba, 0x14, 0x00, 0x00, 0x00\n"        /* mov edx, 20  */
        ".byte 0xbe, 0x1e, 0x00, 0x00, 0x00\n"        /* mov esi, 30  */
        ".byte 0x83, 0xc0, 0x05, 0x90, 0x90, 0x90\n"  /* slot 1       */
        ".byte 0x83, 0xc1, 0x03, 0x90, 0x90, 0x90\n"  /* slot 2       */
        ".byte 0xc1, 0xe2, 0x01, 0x90, 0x90, 0x90\n"  /* slot 3       */
        ".byte 0x83, 0xc6, 0x04, 0x90, 0x90, 0x90\n"  /* slot 4       */
        ".byte 0x01, 0xc8\n"                          /* add eax, ecx */
        ".byte 0x01, 0xd0\n"                          /* add eax, edx */
        ".byte 0x01, 0xf0\n"                          /* add eax, esi */
        : "=a"(result)
        :
        : "ecx", "edx", "esi");
    return result;
}

static void make_page_writable(void *addr) {
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(getpagesize() - 1);
    mprotect((void *)page, (size_t)getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
}

static uint8_t *find_anchor(uint8_t *code, size_t search_len) {
    for (size_t i = 0; i + SLOT_LEN <= search_len; ++i) {
        if (memcmp(code + i, slot1_variants[0].bytes, SLOT_LEN) == 0) {
            return code + i;
        }
    }
    return NULL;
}

static void dump_slot_bytes(const uint8_t *slot) {
    for (int i = 0; i < SLOT_LEN; ++i) {
        printf("%02x ", slot[i]);
    }
}

int main(void) {
    uint8_t *code = (uint8_t *)target_func;
    uint8_t *slots[SLOT_COUNT];

    make_page_writable(code);

    slots[0] = find_anchor(code, 128);
    if (!slots[0]) {
        fprintf(stderr, "failed to find slot 1 anchor bytes\n");
        return 1;
    }

    for (int i = 1; i < SLOT_COUNT; ++i) {
        slots[i] = slots[0] + (i * SLOT_LEN);
    }

    printf("=== Self-Modifying Test: 4 instruction strings, 5 rewrites each ===\n");
    printf("slot 1 anchor offset: +%ld bytes from function start\n\n", (long)(slots[0] - code));

    for (int round = 0; round <= PATCH_ROUNDS; ++round) {
        int value = target_func();

        printf("[round %d] target_func() = %d\n", round, value);
        for (int slot = 0; slot < SLOT_COUNT; ++slot) {
            printf("  slot %d: %-24s bytes: ", slot + 1, all_variants[slot][round].desc);
            dump_slot_bytes(slots[slot]);
            printf("\n");
        }

        if (round == PATCH_ROUNDS) {
            break;
        }

        printf("  applying patch round %d\n", round + 1);
        for (int slot = 0; slot < SLOT_COUNT; ++slot) {
            memcpy(slots[slot], all_variants[slot][round + 1].bytes, SLOT_LEN);
        }
        __builtin___clear_cache((char *)slots[0], (char *)slots[SLOT_COUNT - 1] + SLOT_LEN);
        printf("\n");
    }

    return 0;
}
