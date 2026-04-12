#pragma once
#include <stdio.h>
#include "stdint.h"
#include "vector"
#include "string"
#include <stdexcept>
#include <cctype>
#include "iostream"
#include "filesystem"
#include "fstream"
#include "string"

struct instructionData {
    uint64_t pc;
    std::string kind;
    uint64_t branchTarget;
    uint64_t fallthroughAddr;
    uint64_t translatedBlockBase;
    std::vector<uint8_t> bytes;
    std::string disassembly;
    std::string symbol;
};

struct ElfSymbol {
    std::string name;
    uint64_t addr;
    uint64_t size;
    bool isData;
};

// Build a contiguous memory image from instruction bytes.
// Sets base to the lowest pc and entry to the first instruction pc.
std::vector<uint8_t> buildMemoryImage(
    const std::vector<instructionData>& insns,
    uint64_t& base,
    uint64_t& entry,
    uint8_t pad = 0xCC,
    const std::string& targetTriple = "",
    uint64_t* dataStart = nullptr,
    uint64_t* dataEnd = nullptr,
    std::vector<ElfSymbol>* symbols = nullptr);

// Writes a minimal ELF64 little-endian x86_64 executable with a single LOAD segment.
bool writeElfX64LE(
    const std::filesystem::path& outPath,
    const std::vector<uint8_t>& image,
    uint64_t base,
    uint64_t entry,
    uint64_t dataStart = 0,
    uint64_t dataEnd = 0,
    const std::vector<ElfSymbol>* symbols = nullptr);

// Reads target triple from a key=value file at infoPath.
// Expected key: target_triple
std::string readTargetTriple(const std::filesystem::path& infoPath);

// Infers the target triple from an ELF file and writes it to infoPath.
// Returns true on success.
bool writeTargetTripleFromElf(
    const std::filesystem::path& elfPath,
    const std::filesystem::path& infoPath);

    
struct VariantChunk {
    uint64_t start_pc;
    std::vector<uint8_t> bytes;
};
struct VariantGroup {
    uint64_t pc;
    std::vector<VariantChunk> variants;
};