#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "main.hpp"

// Emits raw bytes for a boxed handler that increments a counter and dispatches
// to the chosen variant using a direct branch. Variant bytes are relocated and
// embedded inline so Ghidra can trace the full CFG as one function.
std::vector<uint8_t> emitBoxedHandler(
    const std::string& targetTriple,
    uint64_t stubAddr,
    uint64_t counterAddr,
    const std::vector<VariantChunk>& variantChunks,
    uint64_t continuationAddr = 0);
