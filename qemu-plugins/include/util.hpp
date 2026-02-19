#pragma once
#include "string"
#include "stdlib.h"
#include <cstdint>
#include "qemu/qemu-plugin.h"

/**
 * Convert bytes into a hex string.
 * @param data Pointer to the buffer to write
 * @param len Number of bytes in the buffer
 */
std::string bytes_to_hex(const uint8_t *data, size_t len);

/**
 * Disassemble a given qemu instruction with error handling.
 * @param insn Instruction to analyze.
 */
static inline std::string safe_disas(struct qemu_plugin_insn *insn);

/**
 * Get the 64 bit value from a "0x7ff...f90" type string. For example, if you 
 * had a string "0x400090", it would set out_target = 0x40090
 * 
 * @param d String buffer. Assumed to be null terminated.
 * @param out_target Target value
 * @return 0 on error, 1 on success.
 */
static int parse_imm_target(const char *d, uint64_t *out_target);