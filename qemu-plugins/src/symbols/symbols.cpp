#include "symbols.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <inttypes.h>

#include <llvm/Demangle/Demangle.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>

#include <stdio.h>

namespace {

static std::string to_std_string(llvm::StringRef s) {
    return std::string(s.data(), s.size());
}

static bool parse_uint64_text(llvm::StringRef text, uint64_t& out) {
    std::string s = text.trim().str();
    if (s.empty()) return false;

    errno = 0;
    char* end = nullptr;
    unsigned long long value = std::strtoull(s.c_str(), &end, 0);
    if (errno == ERANGE || end == s.c_str()) {
        return false;
    }
    while (end && *end != '\0') {
        if (!std::isspace(static_cast<unsigned char>(*end))) {
            return false;
        }
        end++;
    }

    out = static_cast<uint64_t>(value);
    return true;
}

static bool parse_json_uint64(const llvm::json::Value& value, uint64_t& out) {
    if (std::optional<uint64_t> u = value.getAsUINT64()) {
        out = *u;
        return true;
    }
    if (std::optional<int64_t> i = value.getAsInteger()) {
        if (*i < 0) return false;
        out = static_cast<uint64_t>(*i);
        return true;
    }
    if (std::optional<double> d = value.getAsNumber()) {
        if (!std::isfinite(*d) || *d < 0.0) return false;
        double integral = 0.0;
        if (std::modf(*d, &integral) != 0.0) return false;
        if (integral > static_cast<double>(std::numeric_limits<uint64_t>::max())) {
            return false;
        }
        out = static_cast<uint64_t>(integral);
        return true;
    }
    if (std::optional<llvm::StringRef> s = value.getAsString()) {
        return parse_uint64_text(*s, out);
    }
    return false;
}

static bool get_json_uint64(const llvm::json::Object& obj, llvm::StringRef key, uint64_t& out) {
    if (const llvm::json::Value* value = obj.get(key)) {
        return parse_json_uint64(*value, out);
    }
    return false;
}

static bool get_any_json_uint64(
    const llvm::json::Object& obj,
    std::initializer_list<const char*> keys,
    uint64_t& out) {
    for (const char* key : keys) {
        if (get_json_uint64(obj, key, out)) {
            return true;
        }
    }
    return false;
}

static std::string get_first_json_string(
    const llvm::json::Object& obj,
    std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
        if (std::optional<llvm::StringRef> value = obj.getString(key)) {
            std::string s = to_std_string(*value);
            if (!s.empty()) {
                return s;
            }
        }
    }
    return {};
}

static bool json_symbol_kind_is_code(const llvm::json::Object& sym) {
    std::optional<llvm::StringRef> kind_ref = sym.getString("kind");
    if (!kind_ref || kind_ref->empty()) {
        return true;
    }

    std::string kind = kind_ref->lower();
    return kind == "function" ||
           kind == "func" ||
           kind == "code" ||
           kind == "minimal" ||
           kind == "unknown" ||
           kind == "notype" ||
           kind == "stub" ||
           kind == "plt";
}

static bool permissions_are_executable(llvm::StringRef permissions) {
    return permissions.contains_insensitive("x") ||
           permissions.contains_insensitive("exec");
}

static bool add_with_overflow(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > std::numeric_limits<uint64_t>::max() - a) {
        return true;
    }
    out = a + b;
    return false;
}

static void replace_all(std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static bool is_hex_lower_string(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

static std::string prettify_symbol_name(std::string name) {
    // Rust mangling artifacts that survive demangle().
    replace_all(name, "$LT$", "<");
    replace_all(name, "$GT$", ">");
    replace_all(name, "$LP$", "(");
    replace_all(name, "$RP$", ")");
    replace_all(name, "$C$", ",");
    replace_all(name, "$u20$", " ");
    replace_all(name, "..", "::");

    // Strip Rust hash suffixes like ::h45490925b0e0941b.
    const size_t hpos = name.rfind("::h");
    if (hpos != std::string::npos) {
        const std::string tail = name.substr(hpos + 3);
        if (tail.size() >= 8 && tail.size() <= 32 && is_hex_lower_string(tail)) {
            name.erase(hpos);
        }
    }
    return name;
}

static std::string collapse_generic_arguments(std::string name) {
    std::string out;
    out.reserve(name.size());

    int depth = 0;
    bool emitted_ellipsis_for_group = false;

    for (char c : name) {
        if (c == '<') {
            if (depth == 0) {
                out.push_back('<');
                out.append("...");
                emitted_ellipsis_for_group = true;
            }
            depth++;
            continue;
        }
        if (c == '>') {
            if (depth > 0) {
                depth--;
                if (depth == 0) {
                    out.push_back('>');
                    emitted_ellipsis_for_group = false;
                }
                continue;
            }
        }

        if (depth == 0) {
            out.push_back(c);
        } else if (!emitted_ellipsis_for_group) {
            out.append("...");
            emitted_ellipsis_for_group = true;
        }
    }

    return out;
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
            {},
            0,
            0,
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

bool SymbolResolver::load_json(const std::string& json_path, uint64_t runtime_base) {
    syms_.clear();
    sections_.clear();
    min_load_vaddr_ = 0;
    load_bias_ = 0;
    runtimeBase = 0;
    last_runtime_pc_ = 0;
    last_idx_ = -1;

    auto buffer_or_err = llvm::MemoryBuffer::getFile(json_path);
    if (!buffer_or_err) {
        fprintf(stderr, "SymbolResolver: failed to open JSON symbols %s\n", json_path.c_str());
        return false;
    }

    llvm::Expected<llvm::json::Value> parsed_or_err = llvm::json::parse((*buffer_or_err)->getBuffer());
    if (!parsed_or_err) {
        std::string err = llvm::toString(parsed_or_err.takeError());
        fprintf(stderr, "SymbolResolver: failed to parse JSON symbols %s: %s\n",
                json_path.c_str(), err.c_str());
        return false;
    }

    const llvm::json::Object* root = parsed_or_err->getAsObject();
    if (!root) {
        fprintf(stderr, "SymbolResolver: JSON symbols root must be an object: %s\n", json_path.c_str());
        return false;
    }

    struct JsonObjectInfo {
        uint64_t static_base = 0;
        uint64_t runtime_base = 0;
        uint64_t bias = 0;
        bool has_static_base = false;
        bool has_runtime_base = false;
        bool has_bias = false;
    };

    std::unordered_map<std::string, JsonObjectInfo> objects;
    std::optional<uint64_t> exec_bias;
    std::optional<uint64_t> any_bias;
    bool saw_runtime_only_symbol = false;

    auto record_bias = [&](uint64_t static_address, uint64_t runtime_address, bool executable) {
        if (runtime_address < static_address) {
            return;
        }
        const uint64_t bias = runtime_address - static_address;
        if (executable && !exec_bias) {
            exec_bias = bias;
        }
        if (!any_bias) {
            any_bias = bias;
        }
    };

    if (const llvm::json::Array* object_array = root->getArray("objects")) {
        for (const llvm::json::Value& object_value : *object_array) {
            const llvm::json::Object* object = object_value.getAsObject();
            if (!object) continue;

            std::string id = get_first_json_string(*object, {"id", "file_path", "real_path"});
            if (id.empty()) {
                continue;
            }

            JsonObjectInfo info{};
            info.has_static_base = get_any_json_uint64(*object, {"static_base", "image_base"}, info.static_base);
            info.has_runtime_base = get_any_json_uint64(*object, {"runtime_base", "load_base"}, info.runtime_base);
            if (info.has_static_base && info.has_runtime_base && info.runtime_base >= info.static_base) {
                info.bias = info.runtime_base - info.static_base;
                info.has_bias = true;
                record_bias(info.static_base, info.runtime_base, false);
            }

            if (const llvm::json::Array* section_array = object->getArray("sections")) {
                for (const llvm::json::Value& section_value : *section_array) {
                    const llvm::json::Object* section = section_value.getAsObject();
                    if (!section) continue;

                    uint64_t static_address = 0;
                    uint64_t runtime_address = 0;
                    uint64_t size = 0;
                    bool has_static_address = get_any_json_uint64(
                        *section, {"static_address", "address", "addr", "start"}, static_address);
                    const bool has_runtime_address = get_json_uint64(*section, "runtime_address", runtime_address);
                    if (!has_static_address && has_runtime_address && info.has_bias &&
                        runtime_address >= info.bias) {
                        static_address = runtime_address - info.bias;
                        has_static_address = true;
                    }
                    if (!has_static_address ||
                        !get_any_json_uint64(*section, {"size", "length"}, size) ||
                        size == 0) {
                        continue;
                    }

                    uint64_t end = 0;
                    if (add_with_overflow(static_address, size, end)) {
                        continue;
                    }

                    std::string name = get_first_json_string(*section, {"name", "section"});
                    std::string permissions = get_first_json_string(*section, {"permissions", "perms"});
                    const bool is_exec =
                        permissions_are_executable(permissions) ||
                        name == ".text" ||
                        name.find("text") != std::string::npos;

                    SectionRange range{};
                    range.start = static_address;
                    range.end = end;
                    range.valid = true;
                    range.is_exec = is_exec;
                    range.name = std::move(name);
                    sections_.push_back(std::move(range));

                    if (has_runtime_address) {
                        record_bias(static_address, runtime_address, is_exec);
                    }
                }
            }

            objects.emplace(std::move(id), info);
        }
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

    const llvm::json::Array* symbols = root->getArray("symbols");
    if (!symbols) {
        fprintf(stderr, "SymbolResolver: JSON symbols missing symbols array: %s\n", json_path.c_str());
        return false;
    }

    for (const llvm::json::Value& symbol_value : *symbols) {
        const llvm::json::Object* symbol = symbol_value.getAsObject();
        if (!symbol || !json_symbol_kind_is_code(*symbol)) {
            continue;
        }

        std::string name = get_first_json_string(*symbol, {"demangled_name", "name", "linkage_name"});
        if (name.empty()) {
            continue;
        }

        const JsonObjectInfo* object_info = nullptr;
        if (std::optional<llvm::StringRef> object_id = symbol->getString("object_id")) {
            auto it = objects.find(to_std_string(*object_id));
            if (it != objects.end()) {
                object_info = &it->second;
            }
        }

        uint64_t start = 0;
        uint64_t relative_address = 0;
        uint64_t runtime_address = 0;
        bool has_start = get_any_json_uint64(
            *symbol,
            {"static_address", "address", "addr", "start", "value"},
            start);
        if (!has_start &&
            get_json_uint64(*symbol, "object_relative_address", relative_address)) {
            start = relative_address;
            if (object_info && object_info->has_static_base) {
                if (add_with_overflow(object_info->static_base, relative_address, start)) {
                    continue;
                }
            }
            has_start = true;
        }

        const bool has_runtime_address =
            get_json_uint64(*symbol, "runtime_address", runtime_address);
        if (has_start && has_runtime_address) {
            record_bias(start, runtime_address, true);
        }
        if (!has_start && has_runtime_address && object_info && object_info->has_bias &&
            runtime_address >= object_info->bias) {
            start = runtime_address - object_info->bias;
            has_start = true;
        }
        if (!has_start && has_runtime_address && any_bias && runtime_address >= *any_bias) {
            start = runtime_address - *any_bias;
            has_start = true;
        }
        if (!has_start && has_runtime_address) {
            start = runtime_address;
            has_start = true;
            saw_runtime_only_symbol = true;
        }
        if (!has_start || start == 0) {
            continue;
        }

        uint64_t end = 0;
        uint64_t size = 0;
        uint64_t runtime_end = 0;
        if (get_any_json_uint64(*symbol, {"static_end", "end"}, end) && end <= start) {
            end = 0;
        } else if (end == 0 &&
                   get_json_uint64(*symbol, "runtime_end", runtime_end)) {
            if (has_runtime_address && runtime_end > runtime_address) {
                if (add_with_overflow(start, runtime_end - runtime_address, end)) {
                    end = 0;
                }
            } else if (any_bias && runtime_end >= *any_bias) {
                end = runtime_end - *any_bias;
            }
            if (end <= start) {
                end = 0;
            }
        }
        if (end == 0 && get_any_json_uint64(*symbol, {"size", "length"}, size) && size > 0) {
            if (add_with_overflow(start, size, end)) {
                end = 0;
            }
        }

        std::string file;
        uint32_t line = 0;
        uint32_t column = 0;
        if (const llvm::json::Object* loc = symbol->getObject("source_location")) {
            file = get_first_json_string(*loc, {"file", "path"});
            uint64_t tmp = 0;
            if (get_json_uint64(*loc, "line", tmp)) {
                line = static_cast<uint32_t>(std::min<uint64_t>(tmp, std::numeric_limits<uint32_t>::max()));
            }
            if (get_json_uint64(*loc, "column", tmp)) {
                column = static_cast<uint32_t>(std::min<uint64_t>(tmp, std::numeric_limits<uint32_t>::max()));
            }
        } else {
            file = get_first_json_string(*symbol, {"file", "source_file"});
            uint64_t tmp = 0;
            if (get_json_uint64(*symbol, "line", tmp)) {
                line = static_cast<uint32_t>(std::min<uint64_t>(tmp, std::numeric_limits<uint32_t>::max()));
            }
            if (get_json_uint64(*symbol, "column", tmp)) {
                column = static_cast<uint32_t>(std::min<uint64_t>(tmp, std::numeric_limits<uint32_t>::max()));
            }
        }

        syms_.push_back(SymRange{
            start,
            end,
            std::move(name),
            std::move(file),
            line,
            column,
            find_section_idx(start),
        });
    }

    if (syms_.empty()) {
        fprintf(stderr, "SymbolResolver: JSON symbols file contains no code symbols: %s\n",
                json_path.c_str());
        return false;
    }

    uint64_t min_exec_addr = std::numeric_limits<uint64_t>::max();
    uint64_t min_any_addr = std::numeric_limits<uint64_t>::max();
    for (const auto& sec : sections_) {
        if (!sec.valid || sec.start == 0) continue;
        if (sec.start < min_any_addr) {
            min_any_addr = sec.start;
        }
        if (sec.is_exec && sec.start < min_exec_addr) {
            min_exec_addr = sec.start;
        }
    }
    if (min_exec_addr != std::numeric_limits<uint64_t>::max()) {
        min_load_vaddr_ = min_exec_addr;
    } else if (min_any_addr != std::numeric_limits<uint64_t>::max()) {
        min_load_vaddr_ = min_any_addr;
    } else {
        for (const auto& sym : syms_) {
            if (sym.start != 0 && (min_load_vaddr_ == 0 || sym.start < min_load_vaddr_)) {
                min_load_vaddr_ = sym.start;
            }
        }
    }

    sort_and_infer_ends_();

    if (exec_bias || any_bias) {
        load_bias_ = exec_bias ? *exec_bias : *any_bias;
        if (add_with_overflow(min_load_vaddr_, load_bias_, runtimeBase)) {
            runtimeBase = runtime_base;
        }
    } else if (saw_runtime_only_symbol) {
        load_bias_ = 0;
        runtimeBase = runtime_base;
    } else if (compute_min_load_vaddr_()) {
        if (runtime_base >= min_load_vaddr_) {
            load_bias_ = runtime_base - min_load_vaddr_;
        } else {
            // runtime_base (ELF segment base) is below min_load_vaddr_ (first
            // section address): this is a non-PIE binary where static
            // addresses already equal runtime addresses, so no adjustment.
            load_bias_ = 0;
        }
        runtimeBase = runtime_base;
    } else {
        load_bias_ = runtime_base;
        runtimeBase = runtime_base;
    }

    fprintf(stderr, "SymbolResolver: loaded %zu symbols from JSON %s\n",
            syms_.size(), json_path.c_str());
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

    out_hit.name = s.name.c_str();
    out_hit.sym_start = s.start;
    out_hit.sym_end = s.end;
    out_hit.offset = elf_pc - s.start;
    out_hit.elf_pc = elf_pc;
    out_hit.file = s.file.empty() ? nullptr : s.file.c_str();
    out_hit.line = s.line;
    out_hit.column = s.column;
    return true;
}

bool SymbolResolver::lookup(uint64_t runtime_pc, Hit& out_hit) const {
    if (syms_.empty()) return false;

    uint64_t elf_pc = runtime_pc - load_bias_;
    if (lookup_elf_pc_(elf_pc, out_hit)) {
        return true;
    }

    // Some QEMU user-mode targets report PCs as image virtual addresses even
    // when start_code looks like a segment base. Try the unadjusted PC before
    // giving up so JSON-exported static symbols still populate branchlog CSVs.
    if (load_bias_ != 0) {
        return lookup_elf_pc_(runtime_pc, out_hit);
    }

    return false;
}

std::string SymbolResolver::format_for_display(const Hit& hit) const {
    if (!hit.name || hit.name[0] == '\0') {
        return {};
    }

    std::string base = hit.name;
    if (display_policy_enabled_.load(std::memory_order_relaxed)) {
        base = prettify_symbol_name(std::move(base));
        base = collapse_generic_arguments(std::move(base));
    }

    if (hit.offset == 0 || hide_symbol_offsets_.load(std::memory_order_relaxed)) {
        return base;
    }

    char off[32];
    snprintf(off, sizeof(off), "+0x%" PRIx64, hit.offset);
    base += off;
    return base;
}

void SymbolResolver::set_display_policy_enabled(bool enabled) {
    display_policy_enabled_.store(enabled, std::memory_order_relaxed);
}

bool SymbolResolver::display_policy_enabled() const {
    return display_policy_enabled_.load(std::memory_order_relaxed);
}

void SymbolResolver::set_hide_symbol_offsets(bool enabled) {
    hide_symbol_offsets_.store(enabled, std::memory_order_relaxed);
}

bool SymbolResolver::hide_symbol_offsets() const {
    return hide_symbol_offsets_.load(std::memory_order_relaxed);
}
