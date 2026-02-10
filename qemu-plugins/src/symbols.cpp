#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Block the QEMU-specific elf.h and pull in glibc's definitions that libelf expects.
#ifndef QEMU_ELF_H
#define QEMU_ELF_H
#endif
#include </usr/include/elf.h>
#include <libelf.h>
#include <gelf.h>

#include "symbols.hpp"


#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>

static bool read_section_bytes(Elf_Scn* scn, std::vector<char>& out) {
    out.clear();
    Elf_Data* data = elf_getdata(scn, nullptr);
    if (!data || !data->d_buf || data->d_size == 0) return false;
    out.resize(data->d_size);
    memcpy(out.data(), data->d_buf, data->d_size);
    return true;
}

int SymbolResolver::compare_sym_start(const void* a, const void* b) {
    const auto* sa = reinterpret_cast<const SymRange*>(a);
    const auto* sb = reinterpret_cast<const SymRange*>(b);
    if (sa->start < sb->start) return -1;
    if (sa->start > sb->start) return 1;

    // tie-breaker: longer first
    uint64_t la = (sa->end > sa->start) ? (sa->end - sa->start) : 0;
    uint64_t lb = (sb->end > sb->start) ? (sb->end - sb->start) : 0;
    if (la > lb) return -1;
    if (la < lb) return 1;
    return 0;
}

bool SymbolResolver::compute_min_load_vaddr_(int fd, uint64_t& out_min_vaddr) const {
    out_min_vaddr = UINT64_MAX;

    Elf* e = elf_begin(fd, ELF_C_READ, nullptr);
    if (!e) return false;

    size_t phnum = 0;
    if (elf_getphdrnum(e, &phnum) != 0) {
        elf_end(e);
        return false;
    }

    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (!gelf_getphdr(e, i, &phdr)) continue;
        if (phdr.p_type == PT_LOAD) {
            if (phdr.p_vaddr < out_min_vaddr) out_min_vaddr = phdr.p_vaddr;
        }
    }

    elf_end(e);
    return (out_min_vaddr != UINT64_MAX);
}

bool SymbolResolver::parse_elf_(const std::string& elf_path) {
    syms_.clear();
    strs_.clear();
    sections_.clear();
    min_load_vaddr_ = 0;
    last_runtime_pc_ = 0;
    last_idx_ = -1;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "SymbolResolver: libelf init failed\n");
        return false;
    }

    int fd = open(elf_path.c_str(), O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "SymbolResolver: open(%s) failed: %s\n",
                elf_path.c_str(), strerror(errno));
        return false;
    }

    if (!compute_min_load_vaddr_(fd, min_load_vaddr_)) {
        fprintf(stderr, "SymbolResolver: failed to compute PT_LOAD min vaddr for %s\n",
                elf_path.c_str());
        close(fd);
        return false;
    }

    Elf* e = elf_begin(fd, ELF_C_READ, nullptr);
    if (!e) {
        fprintf(stderr, "SymbolResolver: elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        return false;
    }

    // We need to load string tables referenced by .symtab/.dynsym (sh_link)
    struct StrInfo { size_t off = 0; size_t len = 0; };
    // Most ELFs won't have anywhere near 4096 sections, but keep it simple & safe-ish
    std::vector<StrInfo> strinfo(4096);

    size_t shnum = 0;
    if (elf_getshdrnum(e, &shnum) != 0) {
        elf_end(e);
        close(fd);
        return false;
    }
    sections_.assign(shnum, SectionRange{});

    size_t shstrndx = 0;
    if (elf_getshdrstrndx(e, &shstrndx) != 0) {
        elf_end(e);
        close(fd);
        return false;
    }

    // Pass 1: find symtab/dynsym sections and read their strtabs into a single buffer
    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(e, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        size_t scn_idx = elf_ndxscn(scn);
        if (scn_idx < sections_.size()) {
            sections_[scn_idx].start = shdr.sh_addr;
            sections_[scn_idx].end = shdr.sh_addr + shdr.sh_size;
            sections_[scn_idx].valid = true;
            const char* secname = elf_strptr(e, shstrndx, shdr.sh_name);
            sections_[scn_idx].name = secname ? secname : "";
            bool is_exec = (shdr.sh_flags & SHF_EXECINSTR) != 0;
            if (is_exec && secname && strstr(secname, ".plt")) {
                sections_[scn_idx].is_plt = true;
                sections_[scn_idx].plt_entry_size = (shdr.sh_entsize != 0) ? shdr.sh_entsize : 16;
                sections_[scn_idx].plt_reserved_slots = (secname && strcmp(secname, ".plt") == 0) ? 1 : 0;
            }
        }

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;
        size_t strndx = static_cast<size_t>(shdr.sh_link);
        if (strndx >= strinfo.size()) continue;
        if (strinfo[strndx].len != 0) continue; // already loaded

        Elf_Scn* strscn = elf_getscn(e, strndx);
        if (!strscn) continue;

        std::vector<char> tmp;
        if (!read_section_bytes(strscn, tmp)) continue;

        size_t old = strs_.size();
        strs_.insert(strs_.end(), tmp.begin(), tmp.end());
        strinfo[strndx].off = old;
        strinfo[strndx].len = tmp.size();
    }

    // Helper: push symbol range
    auto push_sym = [&](uint64_t start, uint64_t end, const char* name, uint16_t shndx) {
        if (!name || name[0] == '\0') return;
        if (start == 0) return;
        syms_.push_back(SymRange{start, end, name, shndx});
    };

    // Pass 2: walk symbols and store pointers into strs_
    scn = nullptr;
    while ((scn = elf_nextscn(e, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;

        size_t strndx = static_cast<size_t>(shdr.sh_link);
        if (strndx >= strinfo.size()) continue;
        if (strinfo[strndx].len == 0) continue;

        const char* strtab = strs_.data() + strinfo[strndx].off;
        size_t strtab_len  = strinfo[strndx].len;

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data || shdr.sh_entsize == 0) continue;

        size_t nsyms = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < nsyms; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, static_cast<int>(i), &sym)) continue;

            unsigned type = GELF_ST_TYPE(sym.st_info);
            if (type != STT_FUNC) continue;

            if (sym.st_name >= strtab_len) continue;
            const char* name = strtab + sym.st_name;

            uint64_t start = static_cast<uint64_t>(sym.st_value);
            uint64_t end   = (sym.st_size != 0) ? (start + static_cast<uint64_t>(sym.st_size)) : start;
            push_sym(start, end, name, static_cast<uint16_t>(sym.st_shndx));
        }
    }

    std::vector<size_t> plt_next_slot(sections_.size(), 0);
    for (size_t i = 0; i < sections_.size(); i++) {
        if (sections_[i].is_plt) {
            if (sections_[i].plt_entry_size == 0) {
                sections_[i].plt_entry_size = 16;
            }
            plt_next_slot[i] = sections_[i].plt_reserved_slots;
        }
    }

    // Pass 3: synthesize PLT symbols from relocation order
    scn = nullptr;
    while ((scn = elf_nextscn(e, scn)) != nullptr) {
        GElf_Shdr rel_shdr;
        if (!gelf_getshdr(scn, &rel_shdr)) continue;
        if (rel_shdr.sh_type != SHT_RELA && rel_shdr.sh_type != SHT_REL) continue;

        size_t plt_idx = SIZE_MAX;
        size_t target_idx = static_cast<size_t>(rel_shdr.sh_info);
        if (target_idx < sections_.size() && sections_[target_idx].is_plt) {
            plt_idx = target_idx;
        } else {
            const char* relname = nullptr;
            size_t rel_idx = elf_ndxscn(scn);
            if (rel_idx < sections_.size()) {
                relname = sections_[rel_idx].name.c_str();
            }
            std::string candidate;
            if (relname && relname[0] != '\0') {
                const char* prefix = nullptr;
                if (!strncmp(relname, ".rela", 5)) prefix = ".rela";
                else if (!strncmp(relname, ".rel", 4)) prefix = ".rel";
                if (prefix) {
                    const char* remainder = relname + strlen(prefix);
                    if (*remainder == '.' || *remainder == '\0') {
                        candidate = remainder;
                    }
                }
            }
            if (!candidate.empty()) {
                for (size_t i = 0; i < sections_.size(); i++) {
                    if (!sections_[i].is_plt) continue;
                    if (sections_[i].name == candidate) {
                        plt_idx = i;
                        break;
                    }
                }
            }
        }

        if (plt_idx == SIZE_MAX || !sections_[plt_idx].is_plt) continue;

        Elf_Data* rel_data = elf_getdata(scn, nullptr);
        if (!rel_data || rel_shdr.sh_entsize == 0) continue;
        size_t rel_count = rel_shdr.sh_size / rel_shdr.sh_entsize;
        if (rel_count == 0) continue;

        size_t symtab_idx = static_cast<size_t>(rel_shdr.sh_link);
        Elf_Scn* sym_scn = elf_getscn(e, symtab_idx);
        if (!sym_scn) continue;

        GElf_Shdr sym_shdr;
        if (!gelf_getshdr(sym_scn, &sym_shdr)) continue;
        Elf_Data* sym_data = elf_getdata(sym_scn, nullptr);
        if (!sym_data || sym_shdr.sh_entsize == 0) continue;

        size_t strndx = static_cast<size_t>(sym_shdr.sh_link);
        if (strndx >= strinfo.size()) continue;
        if (strinfo[strndx].len == 0) continue;
        const char* strtab = strs_.data() + strinfo[strndx].off;
        size_t strtab_len = strinfo[strndx].len;

        for (size_t i = 0; i < rel_count; i++) {
            size_t sym_idx = 0;
            if (rel_shdr.sh_type == SHT_RELA) {
                GElf_Rela rela;
                if (!gelf_getrela(rel_data, static_cast<int>(i), &rela)) continue;
                sym_idx = GELF_R_SYM(rela.r_info);
            } else {
                GElf_Rel rel;
                if (!gelf_getrel(rel_data, static_cast<int>(i), &rel)) continue;
                sym_idx = GELF_R_SYM(rel.r_info);
            }

            GElf_Sym sym;
            if (!gelf_getsym(sym_data, static_cast<int>(sym_idx), &sym)) continue;

            const char* name = nullptr;
            if (sym.st_name < strtab_len) {
                name = strtab + sym.st_name;
            }
            if (!name || name[0] == '\0') continue;

            size_t slot_idx = plt_next_slot[plt_idx];
            plt_next_slot[plt_idx]++;

            size_t entry_size = sections_[plt_idx].plt_entry_size ? sections_[plt_idx].plt_entry_size : 16;
            uint64_t start = sections_[plt_idx].start + (entry_size * slot_idx);
            if (start == 0 || start >= sections_[plt_idx].end) continue;

            uint64_t end = std::min(start + entry_size, sections_[plt_idx].end);
            push_sym(start, end, name, static_cast<uint16_t>(plt_idx));
        }
    }

    elf_end(e);
    close(fd);

    sort_and_infer_ends_();
    return true;
}

void SymbolResolver::sort_and_infer_ends_() {
    if (syms_.empty()) return;

    std::qsort(syms_.data(), syms_.size(), sizeof(SymRange), &SymbolResolver::compare_sym_start);

    // Infer end for size==0 symbols using section bounds to avoid spanning unrelated regions.
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

bool SymbolResolver::load(const std::string& elf_path, uint64_t runtime_base) {
    if (!parse_elf_(elf_path)) return false;
    runtimeBase = runtime_base;
    load_bias_ = runtime_base - min_load_vaddr_;
    return true;
}

void SymbolResolver::set_runtime_base(uint64_t runtime_base) {
    load_bias_ = runtime_base - min_load_vaddr_;
    runtimeBase = runtime_base;
    // invalidate cache
    last_runtime_pc_ = 0;
    last_idx_ = -1;
}

bool SymbolResolver::lookup_elf_pc_(uint64_t elf_pc, Hit& out_hit) const {
    if (syms_.empty()) return false;

    // Hot cache
    if (last_idx_ >= 0) {
        const auto& s = syms_[static_cast<size_t>(last_idx_)];
        const bool in_range =
            (elf_pc >= s.start) &&
            ((s.end > s.start) ? (elf_pc < s.end) : (elf_pc == s.start));

        if (in_range) {
            out_hit.name = s.name;
            out_hit.sym_start = s.start;
            out_hit.sym_end = s.end;
            out_hit.offset = elf_pc - s.start;
            out_hit.elf_pc = elf_pc;
            return true;
        }
    }

    // Binary search: last symbol with start <= elf_pc
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

    out_hit.name = s.name;
    out_hit.sym_start = s.start;
    out_hit.sym_end = s.end;
    out_hit.offset = elf_pc - s.start;
    out_hit.elf_pc = elf_pc;
    return true;
}

bool SymbolResolver::lookup(uint64_t runtime_pc, Hit& out_hit) const {
    if (syms_.empty()) return false;

    last_runtime_pc_ = runtime_pc;

    // Translate runtime -> ELF vaddr
    uint64_t elf_pc = runtime_pc - load_bias_;
    return lookup_elf_pc_(elf_pc, out_hit);
}
