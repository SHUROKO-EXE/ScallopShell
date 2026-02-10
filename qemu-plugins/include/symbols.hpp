#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>



class SymbolResolver {
public:
    struct Hit {
        const char* name = nullptr;   // points into owned string buffer; valid while resolver alive
        uint64_t    sym_start = 0;    // ELF virtual address of symbol start
        uint64_t    sym_end = 0;      // ELF virtual address of symbol end (inferred if needed)
        uint64_t    offset = 0;       // elf_pc - sym_start
        uint64_t    elf_pc = 0;       // runtime_pc - load_bias
    };

    uint64_t runtimeBase = 0;
    
    bool initialized = false;

    SymbolResolver() = default;
    ~SymbolResolver() = default;

    // Non-copyable (pointers into internal storage)
    SymbolResolver(const SymbolResolver&) = delete;
    SymbolResolver& operator=(const SymbolResolver&) = delete;

    // Movable
    SymbolResolver(SymbolResolver&&) noexcept = default;
    SymbolResolver& operator=(SymbolResolver&&) noexcept = default;

    // Load symbols from an ELF file and set runtime_base (where the ELF's lowest PT_LOAD vaddr is mapped).
    // Returns true on success (even if no symbols, it can still operate but lookups will miss).
    bool load(const std::string& elf_path, uint64_t runtime_base);

    // Set / update bias without re-parsing symbols (useful if the same ELF loads at different base).
    void set_runtime_base(uint64_t runtime_base);

    // Look up runtime PC. Returns true if a symbol was found and fills out_hit.
    bool lookup(uint64_t runtime_pc, Hit& out_hit) const;

    // Utility: get current load bias (runtime_base - min_pt_load_vaddr)
    uint64_t load_bias() const { return load_bias_; }

    // Utility: number of loaded symbols
    size_t symbol_count() const { return syms_.size(); }

    uint64_t getCurrentRuntimeBase() { return runtimeBase; } 

private:
    struct SymRange {
        uint64_t start;   // ELF vaddr
        uint64_t end;     // ELF vaddr end
        const char* name; // points into strs_ buffer
        uint16_t shndx;   // section index for bounds inference
    };

    struct SectionRange {
        uint64_t start = 0;
        uint64_t end = 0;
        bool     valid = false;
        bool     is_plt = false;
        size_t   plt_entry_size = 0;
        size_t   plt_reserved_slots = 0;
        std::string name;
    };

    static int compare_sym_start(const void* a, const void* b);

    bool parse_elf_(const std::string& elf_path);
    bool compute_min_load_vaddr_(int fd, uint64_t& out_min_vaddr) const;

    void sort_and_infer_ends_();
    bool lookup_elf_pc_(uint64_t elf_pc, Hit& out_hit) const;

    // Parsed data
    std::vector<SymRange> syms_;
    std::vector<char>     strs_;        // concatenated string tables
    std::vector<SectionRange> sections_; // section bounds for range inference
    uint64_t              min_load_vaddr_ = 0;

    // Bias to translate runtime -> ELF vaddr
    uint64_t              load_bias_ = 0;

    // Hot cache (mutable so lookup can update it even if method is const)
    mutable uint64_t      last_runtime_pc_ = 0;
    mutable long          last_idx_ = -1;
};
