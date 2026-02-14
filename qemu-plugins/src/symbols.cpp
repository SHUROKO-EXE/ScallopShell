#include "symbols.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>

#include <llvm/Demangle/Demangle.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>

#include <stdio.h>

namespace {

static std::string to_std_string(llvm::StringRef s) {
    return std::string(s.data(), s.size());
}

} // namespace

bool SymbolResolver::compute_min_load_vaddr_() const {
    return min_load_vaddr_ != 0;
}

bool SymbolResolver::parse_object_(const std::string& binary_path) {
    syms_.clear();
    sections_.clear();
    min_load_vaddr_ = 0;
    last_runtime_pc_ = 0;
    last_idx_ = -1;

    auto buffer_or_err = llvm::MemoryBuffer::getFile(binary_path);
    if (!buffer_or_err) {
        fprintf(stderr, "SymbolResolver: failed to open %s\n", binary_path.c_str());
        return false;
    }

    std::unique_ptr<llvm::MemoryBuffer> buffer = std::move(*buffer_or_err);
    auto obj_or_err = llvm::object::ObjectFile::createObjectFile(buffer->getMemBufferRef());
    if (!obj_or_err) {
        std::string err = llvm::toString(obj_or_err.takeError());
        fprintf(stderr, "SymbolResolver: failed to parse object %s: %s\n", binary_path.c_str(), err.c_str());
        return false;
    }

    llvm::object::ObjectFile& obj = *obj_or_err->get();

    uint64_t min_exec_addr = std::numeric_limits<uint64_t>::max();
    uint64_t min_any_addr = std::numeric_limits<uint64_t>::max();
    for (const llvm::object::SectionRef& sec : obj.sections()) {
        uint64_t addr = sec.getAddress();
        uint64_t size = sec.getSize();
        if (size == 0) {
            continue;
        }

        std::string sec_name;
        if (llvm::Expected<llvm::StringRef> sec_name_or_err = sec.getName()) {
            sec_name = to_std_string(*sec_name_or_err);
        } else {
            llvm::consumeError(sec_name_or_err.takeError());
        }

        SectionRange range{};
        range.start = addr;
        range.end = addr + size;
        range.valid = true;
        range.is_exec = sec.isText();
        range.name = sec_name;
        sections_.push_back(std::move(range));

        if (addr != 0 && addr < min_any_addr) {
            min_any_addr = addr;
        }
        if (sec.isText() && addr != 0 && addr < min_exec_addr) {
            min_exec_addr = addr;
        }
    }

    if (min_exec_addr != std::numeric_limits<uint64_t>::max()) {
        min_load_vaddr_ = min_exec_addr;
    } else if (min_any_addr != std::numeric_limits<uint64_t>::max()) {
        min_load_vaddr_ = min_any_addr;
    } else {
        min_load_vaddr_ = 0;
    }

    auto find_section_idx = [&](uint64_t sym_addr) -> uint16_t {
        for (size_t i = 0; i < sections_.size(); i++) {
            const auto& sec = sections_[i];
            if (!sec.valid) continue;
            if (sym_addr >= sec.start && sym_addr < sec.end) {
                return static_cast<uint16_t>(i);
            }
        }
        return static_cast<uint16_t>(0xffffu);
    };

    for (const llvm::object::SymbolRef& sym : obj.symbols()) {
        llvm::Expected<llvm::object::SymbolRef::Type> type_or_err = sym.getType();
        if (!type_or_err) {
            llvm::consumeError(type_or_err.takeError());
            continue;
        }

        if (*type_or_err != llvm::object::SymbolRef::ST_Function &&
            *type_or_err != llvm::object::SymbolRef::ST_Unknown) {
            continue;
        }

        llvm::Expected<uint64_t> addr_or_err = sym.getAddress();
        if (!addr_or_err) {
            llvm::consumeError(addr_or_err.takeError());
            continue;
        }

        uint64_t start = *addr_or_err;
        if (start == 0) {
            continue;
        }

        llvm::Expected<llvm::StringRef> name_or_err = sym.getName();
        if (!name_or_err) {
            llvm::consumeError(name_or_err.takeError());
            continue;
        }

        std::string raw_name = to_std_string(*name_or_err);
        if (raw_name.empty()) {
            continue;
        }

        std::string pretty_name = llvm::demangle(raw_name);
        if (pretty_name.empty()) {
            pretty_name = raw_name;
        }

        syms_.push_back(SymRange{
            start,
            start, // inferred later
            std::move(pretty_name),
            find_section_idx(start),
        });
    }

    sort_and_infer_ends_();
    return true;
}

void SymbolResolver::sort_and_infer_ends_() {
    if (syms_.empty()) return;

    std::sort(syms_.begin(), syms_.end(), [](const SymRange& a, const SymRange& b) {
        if (a.start != b.start) {
            return a.start < b.start;
        }
        const uint64_t la = (a.end > a.start) ? (a.end - a.start) : 0;
        const uint64_t lb = (b.end > b.start) ? (b.end - b.start) : 0;
        if (la != lb) {
            return la > lb;
        }
        return a.name < b.name;
    });

    for (size_t i = 0; i < syms_.size(); i++) {
        auto& cur = syms_[i];
        if (cur.end > cur.start) {
            continue;
        }

        uint64_t limit = 0;
        if (cur.shndx < sections_.size()) {
            const auto& sec = sections_[cur.shndx];
            if (sec.valid && sec.end > cur.start) {
                limit = sec.end;
            }
        }

        if (i + 1 < syms_.size() && syms_[i + 1].start > cur.start) {
            if (limit == 0) {
                limit = syms_[i + 1].start;
            } else {
                limit = std::min(limit, syms_[i + 1].start);
            }
        }

        if (limit > cur.start) {
            cur.end = limit;
        }
    }
}

bool SymbolResolver::load(const std::string& binary_path, uint64_t runtime_base) {
    if (!parse_object_(binary_path)) return false;

    runtimeBase = runtime_base;
    if (compute_min_load_vaddr_()) {
        load_bias_ = runtime_base - min_load_vaddr_;
    } else {
        // Fallback for objects that do not expose loadable addresses.
        load_bias_ = runtime_base;
    }
    return true;
}

void SymbolResolver::set_runtime_base(uint64_t runtime_base) {
    if (compute_min_load_vaddr_()) {
        load_bias_ = runtime_base - min_load_vaddr_;
    } else {
        load_bias_ = runtime_base;
    }

    runtimeBase = runtime_base;
    last_runtime_pc_ = 0;
    last_idx_ = -1;
}

bool SymbolResolver::lookup_elf_pc_(uint64_t elf_pc, Hit& out_hit) const {
    if (syms_.empty()) return false;

    if (last_idx_ >= 0) {
        const auto& s = syms_[static_cast<size_t>(last_idx_)];
        const bool in_range =
            (elf_pc >= s.start) &&
            ((s.end > s.start) ? (elf_pc < s.end) : (elf_pc == s.start));

        if (in_range) {
            out_hit.name = s.name.c_str();
            out_hit.sym_start = s.start;
            out_hit.sym_end = s.end;
            out_hit.offset = elf_pc - s.start;
            out_hit.elf_pc = elf_pc;
            out_hit.file = nullptr;
            out_hit.line = 0;
            out_hit.column = 0;
            return true;
        }
    }

    size_t lo = 0, hi = syms_.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (syms_[mid].start <= elf_pc) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return false;

    size_t idx = lo - 1;
    const auto& s = syms_[idx];

    const bool in_range =
        (elf_pc >= s.start) &&
        ((s.end > s.start) ? (elf_pc < s.end) : (elf_pc == s.start));

    if (!in_range) return false;

    last_idx_ = static_cast<long>(idx);

    out_hit.name = s.name.c_str();
    out_hit.sym_start = s.start;
    out_hit.sym_end = s.end;
    out_hit.offset = elf_pc - s.start;
    out_hit.elf_pc = elf_pc;
    out_hit.file = nullptr;
    out_hit.line = 0;
    out_hit.column = 0;
    return true;
}

bool SymbolResolver::lookup(uint64_t runtime_pc, Hit& out_hit) const {
    if (syms_.empty()) return false;

    last_runtime_pc_ = runtime_pc;

    uint64_t elf_pc = runtime_pc - load_bias_;
    return lookup_elf_pc_(elf_pc, out_hit);
}
