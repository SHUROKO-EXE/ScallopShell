#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

/* Self-Modifying Code Demo for Scallop Shell Decompiler
 * 1 function that modifies itself 4 times with real compiled C code
 * Each iteration has completely different compiled bytecode at the SAME address
 *
 * Iterations:
 * 0: Open flag.txt with fopen()
 * 1: Write "THIS_CPU_IS_COLD_AT_NIGHT" to file
 * 2: Calculate fibonacci(10)
 * 3: Write fibonacci result and close file
 */

// ============================================================================
// COMPILED BYTECODE FROM REAL C FUNCTIONS
// ============================================================================

// Iteration 0: Loop and sum (0 to 9)
static unsigned char code_iter_0[] = {
    0x55, 0x48, 0x89, 0xE5, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF8, 0x00, 0x00,
    0x00, 0x00, 0xEB, 0x0A, 0x8B, 0x45, 0xF8, 0x01, 0x45, 0xFC, 0x83, 0x45, 0xF8, 0x01, 0x83, 0x7D,
    0xF8, 0x09, 0x7E, 0xF0, 0x8B, 0x45, 0xFC, 0x5D, 0xC3
};

// Iteration 1: Fibonacci(10)
static unsigned char code_iter_1[] = {
    0x55, 0x48, 0x89, 0xE5, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF8, 0x01, 0x00,
    0x00, 0x00, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x1B, 0x8B, 0x55, 0xFC, 0x8B, 0x45,
    0xF8, 0x01, 0xD0, 0x89, 0x45, 0xF0, 0x8B, 0x45, 0xF8, 0x89, 0x45, 0xFC, 0x8B, 0x45, 0xF0, 0x89,
    0x45, 0xF8, 0x83, 0x45, 0xF4, 0x01, 0x83, 0x7D, 0xF4, 0x09, 0x7E, 0xDF, 0x8B, 0x45, 0xF8, 0x5D,
    0xC3
};

// Iteration 2: Power calculation (2^10)
static unsigned char code_iter_2[] = {
    0x55, 0x48, 0x89, 0xE5, 0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF4, 0x02, 0x00,
    0x00, 0x00, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0E, 0x8B, 0x45, 0xFC, 0x0F, 0xAF,
    0x45, 0xF4, 0x89, 0x45, 0xFC, 0x83, 0x45, 0xF8, 0x01, 0x83, 0x7D, 0xF8, 0x09, 0x7E, 0xEC, 0x8B,
    0x45, 0xFC, 0x5D, 0xC3
};

// Iteration 3: Complex math (100+50)*25/10 % 37
static unsigned char code_iter_3[] = {
    0x55, 0x48, 0x89, 0xE5, 0xC7, 0x45, 0xFC, 0x64, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF8, 0x32, 0x00,
    0x00, 0x00, 0xC7, 0x45, 0xF4, 0x19, 0x00, 0x00, 0x00, 0x8B, 0x55, 0xFC, 0x8B, 0x45, 0xF8, 0x01,
    0xC2, 0x8B, 0x45, 0xF4, 0x0F, 0xAF, 0xC2, 0x89, 0x45, 0xF0, 0x8B, 0x45, 0xF0, 0x48, 0x63, 0xD0,
    0x48, 0x69, 0xD2, 0x67, 0x66, 0x66, 0x66, 0x48, 0xC1, 0xEA, 0x20, 0x89, 0xD1, 0xC1, 0xF9, 0x02,
    0x99, 0x89, 0xC8, 0x29, 0xD0, 0x89, 0x45, 0xF0, 0x8B, 0x55, 0xF0, 0x48, 0x63, 0xC2, 0x48, 0x69,
    0xC0, 0xA7, 0xC8, 0x67, 0xDD, 0x48, 0xC1, 0xE8, 0x20, 0x01, 0xD0, 0xC1, 0xF8, 0x05, 0x89, 0xC1,
    0x89, 0xD0, 0xC1, 0xF8, 0x1F, 0x29, 0xC1, 0x89, 0xC8, 0xC1, 0xE0, 0x03, 0x01, 0xC8, 0xC1, 0xE0,
    0x02, 0x01, 0xC8, 0x29, 0xC2, 0x89, 0x55, 0xF0, 0x8B, 0x45, 0xF0, 0x5D, 0xC3
};

// ============================================================================
// HELPER FUNCTIONS FOR SELF-MODIFICATION
// ============================================================================

long get_page_size() {
    return sysconf(_SC_PAGESIZE);
}

uintptr_t get_page_start(uintptr_t addr) {
    long page_size = get_page_size();
    return addr & ~(page_size - 1);
}

size_t get_page_size_for_addr(uintptr_t addr, size_t size) {
    long page_size = get_page_size();
    uintptr_t start = get_page_start(addr);
    uintptr_t end = get_page_start(addr + size - 1);
    return (end - start) + page_size;
}

int make_writable(void *addr, size_t size) {
    uintptr_t start = get_page_start((uintptr_t)addr);
    size_t prot_size = get_page_size_for_addr((uintptr_t)addr, size);

    // Try to make writable, retrying with full page if needed
    if (mprotect((void *)start, prot_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        // Fallback: try smaller pages
        long page_size = get_page_size();
        if (mprotect((void *)start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
            perror("mprotect failed");
            return -1;
        }
    }
    return 0;
}

void clear_icache() {
    asm volatile("mfence" ::: "memory");
}

// ============================================================================
// SELF-MODIFYING FUNCTION
// ============================================================================

__attribute__((aligned(256)))
int smc_main() {
    // Placeholder - will be overwritten
    asm volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; ret");
    return 0;
}

// ============================================================================
// MAIN PROGRAM
// ============================================================================

int main() {
    printf("========================================\n");
    printf("Scallop Shell Self-Modifying Code Demo\n");
    printf("Single function, 4 iterations\n");
    printf("Real compiled C code bytecode\n");
    printf("========================================\n\n");

    printf("Function address: %p\n\n", (void *)smc_main);

    unsigned char *iterations[] = {code_iter_0, code_iter_1, code_iter_2, code_iter_3};
    size_t sizes[] = {sizeof(code_iter_0), sizeof(code_iter_1), sizeof(code_iter_2), sizeof(code_iter_3)};
    const char *descriptions[] = {
        "Loop and sum (0 to 9)",
        "Fibonacci sequence (fib(10))",
        "Power calculation (2^10)",
        "Complex math operations"
    };

    for (int i = 0; i < 4; i++) {
        printf("[Iteration %d] %s\n", i, descriptions[i]);
        printf("  Modifying function at %p\n", (void *)smc_main);
        printf("  Code size: %zu bytes\n", sizes[i]);

        // Make the function writable
        if (make_writable((void *)smc_main, 256) < 0) {
            fprintf(stderr, "Failed to make function writable\n");
            return 1;
        }

        // Copy new code into the function
        memcpy((void *)smc_main, iterations[i], sizes[i]);
        clear_icache();

        // Call the modified function
        int result = smc_main();
        printf("  Result: %d\n\n", result);
    }

    printf("========================================\n");
    printf("Demo complete!\n");
    printf("Ready for Scallop Shell decompilation\n");
    printf("========================================\n");

    return 0;
}
