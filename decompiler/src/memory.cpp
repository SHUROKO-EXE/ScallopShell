#include "main.hpp"
#include "switcher.hpp"
#include <algorithm>
#include <unordered_map>
#include <stdexcept>
#include <capstone/capstone.h>

namespace {
std::vector<uint8_t> relocateX64Chunk(const std::vector<uint8_t>& bytes,
                                      uint64_t oldBase,
                                      uint64_t newBase) {
    if (bytes.empty() || oldBase == newBase)
        return bytes;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Capstone init failed for x86_64 relocation");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    std::vector<uint8_t> out = bytes;
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, bytes.data(), bytes.size(), oldBase, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        throw std::runtime_error("Capstone disasm failed for relocation");
    }

    auto patchDisp = [&](size_t off, size_t size, int64_t value) {
        if (size == 1) {
            if (value < INT8_MIN || value > INT8_MAX) {
                throw std::runtime_error("rel8 out of range for relocation");
            }
            out[off] = static_cast<uint8_t>(value & 0xFF);
        } else if (size == 4) {
            if (value < INT32_MIN || value > INT32_MAX) {
                throw std::runtime_error("rel32 out of range for relocation");
            }
            const uint32_t v = static_cast<uint32_t>(value);
            out[off + 0] = static_cast<uint8_t>(v & 0xFF);
            out[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
            out[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
            out[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        }
    };

    for (size_t i = 0; i < count; ++i) {
        const cs_insn& ci = insn[i];
        if (!ci.detail)
            continue;

        const cs_x86& x86 = ci.detail->x86;
        const uint64_t oldAddr = ci.address;
        const uint64_t newAddr = newBase + (oldAddr - oldBase);

        if ((cs_insn_group(handle, &ci, CS_GRP_JUMP) ||
             cs_insn_group(handle, &ci, CS_GRP_CALL)) &&
            x86.op_count > 0 &&
            x86.operands[0].type == X86_OP_IMM &&
            x86.encoding.imm_size > 0) {
            const int64_t target = static_cast<int64_t>(x86.operands[0].imm);
            const int64_t newDisp = target - static_cast<int64_t>(newAddr + ci.size);
            patchDisp(x86.encoding.imm_offset, x86.encoding.imm_size, newDisp);
        }

        if (x86.encoding.disp_size > 0) {
            for (uint8_t op = 0; op < x86.op_count; ++op) {
                const cs_x86_op& operand = x86.operands[op];
                if (operand.type != X86_OP_MEM)
                    continue;
                if (operand.mem.base != X86_REG_RIP)
                    continue;
                const int64_t target =
                    static_cast<int64_t>(oldAddr + ci.size + operand.mem.disp);
                const int64_t newDisp =
                    target - static_cast<int64_t>(newAddr + ci.size);
                patchDisp(x86.encoding.disp_offset, x86.encoding.disp_size, newDisp);
            }
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
    return out;
}
} // namespace

std::vector<uint8_t> buildMemoryImage(
    const std::vector<instructionData>& insns,
    uint64_t& base,
    uint64_t& entry,
    uint8_t pad,
    const std::string& targetTriple,
    uint64_t* dataStart,
    uint64_t* dataEnd,
    std::vector<ElfSymbol>* symbols) {
    base = 0;
    entry = 0;

    if (insns.empty()) {
        return {}; 
    }

    // First PC is the entry point (caller requested).
    entry = insns.front().pc;

    struct VariantChunk {
        uint64_t start_pc;
        std::vector<uint8_t> bytes;
    };
    struct VariantGroup {
        uint64_t pc;
        std::vector<VariantChunk> variants;
    };

    uint64_t min_pc = UINT64_MAX;
    uint64_t max_end = 0;

    // Check all valid instructions to see what the memory range needs to be
    for (const auto& insn : insns) {
        if (insn.bytes.empty())
            continue;

        // Set the lowest bound of the PC
        if (insn.pc < min_pc)
            min_pc = insn.pc;

        // Minimum PC + Total Size = End PC
        const uint64_t end = insn.pc + static_cast<uint64_t>(insn.bytes.size());
        if (end > max_end)
            max_end = end;
    }

    // If an invalid range is defined, exit
    if (min_pc == UINT64_MAX || max_end <= min_pc) {
        base = 0;
        return {};
    }

    auto buildVariantGroups = [&]() {
        std::unordered_map<uint64_t, std::vector<VariantChunk>> by_pc;
        for (size_t i = 0; i < insns.size(); ++i) {
            const auto& insn = insns[i];
            if (insn.bytes.empty())
                continue;

            VariantChunk chunk{insn.pc, insn.bytes};
            uint64_t expected = insn.fallthroughAddr;
            size_t j = i;
            while (chunk.bytes.size() < 5 && j + 1 < insns.size()) {
                const auto& next = insns[j + 1];
                if (next.bytes.empty() || next.pc != expected)
                    break;
                chunk.bytes.insert(chunk.bytes.end(), next.bytes.begin(), next.bytes.end());
                expected = next.fallthroughAddr;
                ++j;
            }
            auto& variants = by_pc[insn.pc];
            const bool exists = std::any_of(
                variants.begin(), variants.end(),
                [&](const VariantChunk& existing) { return existing.bytes == chunk.bytes; });
            if (!exists) {
                variants.push_back(std::move(chunk));
            }
        }

        std::vector<VariantGroup> groups;
        groups.reserve(by_pc.size());
        for (auto& kv : by_pc) {
            groups.push_back(VariantGroup{kv.first, std::move(kv.second)});
        }
        std::sort(groups.begin(), groups.end(),
                  [](const VariantGroup& a, const VariantGroup& b) { return a.pc < b.pc; });
        return groups;
    };

    const auto groups = buildVariantGroups();

    base = min_pc;
    const uint64_t original_size = max_end - min_pc;
    if (targetTriple.empty()) {
        for (const auto& group : groups) {
            if (group.variants.size() > 1) {
                throw std::runtime_error("targetTriple is required for switcher stubs");
            }
        }
    }

    struct SwitcherLayout {
        uint64_t pc;
        std::vector<uint64_t> variant_addrs;
        uint64_t counter_addr = 0;
        uint64_t stub_addr = 0;
        std::vector<uint8_t> stub_bytes;
    };

    uint64_t arena_cursor = max_end;
    std::vector<SwitcherLayout> switchers;
    switchers.reserve(groups.size());

    for (const auto& group : groups) {
        if (group.variants.size() <= 1)
            continue;

        SwitcherLayout layout;
        layout.pc = group.pc;
        for (const auto& variant : group.variants) {
            layout.variant_addrs.push_back(arena_cursor);
            arena_cursor += variant.bytes.size();
        }
        switchers.push_back(std::move(layout));
    }

    auto alignUp = [](uint64_t value, uint64_t align) {
        return (value + align - 1) & ~(align - 1);
    };

    uint64_t counters_base = alignUp(arena_cursor, 8);
    for (size_t i = 0; i < switchers.size(); ++i) {
        switchers[i].counter_addr = counters_base + i * 8;
    }

    const uint64_t counters_end = counters_base + switchers.size() * 8;
    uint64_t stub_cursor = counters_end;
    for (auto& sw : switchers) {
        sw.stub_addr = stub_cursor;
        sw.stub_bytes = emitSwitcherStub(targetTriple, sw.stub_addr, sw.counter_addr,
                                         sw.variant_addrs);
        stub_cursor += sw.stub_bytes.size();
    }
    const uint64_t final_end = stub_cursor;

    if (dataStart)
        *dataStart = counters_base;
    if (dataEnd)
        *dataEnd = counters_end;

    const uint64_t size = final_end - min_pc;
    std::vector<uint8_t> image(static_cast<size_t>(size), pad);
    std::vector<uint8_t> occupied(static_cast<size_t>(original_size), 0);

    // Place full switcher logic out-of-line and only patch a near jump at the
    // original PC to keep reconstructed code layout close to the original.
    for (const auto& sw : switchers) {
        const uint64_t stub_off = sw.stub_addr - min_pc;
        if (stub_off + sw.stub_bytes.size() > image.size())
            continue;
        std::copy(sw.stub_bytes.begin(), sw.stub_bytes.end(),
                  image.begin() + static_cast<size_t>(stub_off));

        const uint64_t off = sw.pc - min_pc;
        if (off + 5 > image.size())
            continue;

        const int64_t rel =
            static_cast<int64_t>(sw.stub_addr) - static_cast<int64_t>(sw.pc + 5);
        if (rel < INT32_MIN || rel > INT32_MAX) {
            std::cerr << "Warning: switcher jump out of range at pc=0x"
                      << std::hex << sw.pc << " -> 0x" << sw.stub_addr
                      << std::dec << " (switcher skipped)" << std::endl;
            continue;
        }

        image[static_cast<size_t>(off)] = 0xE9;
        const uint32_t rel32 = static_cast<uint32_t>(rel);
        image[static_cast<size_t>(off + 1)] = static_cast<uint8_t>(rel32 & 0xFF);
        image[static_cast<size_t>(off + 2)] = static_cast<uint8_t>((rel32 >> 8) & 0xFF);
        image[static_cast<size_t>(off + 3)] = static_cast<uint8_t>((rel32 >> 16) & 0xFF);
        image[static_cast<size_t>(off + 4)] = static_cast<uint8_t>((rel32 >> 24) & 0xFF);

        const uint64_t occ_end = std::min<uint64_t>(off + 5, original_size);
        for (uint64_t i = off; i < occ_end; ++i) {
            occupied[static_cast<size_t>(i)] = 1;
        }
    }

    for (const auto& group : groups) {
        if (group.variants.size() != 1)
            continue;
        const auto& chunk = group.variants.front();
        const uint64_t off = chunk.start_pc - min_pc;
        if (off + chunk.bytes.size() > image.size())
            continue;
        for (size_t i = 0; i < chunk.bytes.size(); ++i) {
            const uint64_t pos = off + i;
            if (pos < occupied.size() && occupied[static_cast<size_t>(pos)])
                continue;
            image[static_cast<size_t>(pos)] = chunk.bytes[i];
        }
    }

    for (size_t gi = 0, si = 0; gi < groups.size(); ++gi) {
        const auto& group = groups[gi];
        if (group.variants.size() <= 1)
            continue;
        auto& sw = switchers[si++];

        for (size_t vi = 0; vi < group.variants.size(); ++vi) {
            const auto& chunk = group.variants[vi];
            const uint64_t dst = sw.variant_addrs[vi];
            const uint64_t off = dst - min_pc;
            if (off + chunk.bytes.size() > image.size())
                continue;
            std::vector<uint8_t> relocated = chunk.bytes;
            if (targetTriple.rfind("x86_64", 0) == 0) {
                try {
                    relocated = relocateX64Chunk(chunk.bytes, chunk.start_pc, dst);
                } catch (const std::exception& ex) {
                    std::cerr << "Warning: relocation failed at pc=0x"
                              << std::hex << chunk.start_pc << " -> 0x" << dst
                              << std::dec << ": " << ex.what()
                              << " (using original bytes)" << std::endl;
                }
            }
            std::copy(relocated.begin(), relocated.end(),
                      image.begin() + static_cast<size_t>(off));
        }
    }

    for (const auto& sw : switchers) {
        const uint64_t counter_off = sw.counter_addr - min_pc;
        if (counter_off + 8 <= image.size()) {
            for (size_t i = 0; i < 8; ++i) {
                image[static_cast<size_t>(counter_off + i)] = 0;
            }
        }
    }

    if (symbols) {
        symbols->clear();
        for (const auto& sw : switchers) {
            ElfSymbol sym{};
            sym.name = "switcher_" + std::to_string(sw.pc);
            sym.addr = sw.pc;
            sym.size = 5;
            sym.isData = false;
            symbols->push_back(sym);

            ElfSymbol body{};
            body.name = "switcher_body_" + std::to_string(sw.pc);
            body.addr = sw.stub_addr;
            body.size = sw.stub_bytes.size();
            body.isData = false;
            symbols->push_back(body);

            ElfSymbol counter{};
            counter.name = "switcher_counter_" + std::to_string(sw.pc);
            counter.addr = sw.counter_addr;
            counter.size = 8;
            counter.isData = true;
            symbols->push_back(counter);

        }

        for (size_t gi = 0, si = 0; gi < groups.size(); ++gi) {
            const auto& group = groups[gi];
            if (group.variants.size() <= 1)
                continue;
            const auto& sw = switchers[si++];
            for (size_t vi = 0; vi < group.variants.size(); ++vi) {
                const auto& chunk = group.variants[vi];
                ElfSymbol sym{};
                sym.name = "variant_" + std::to_string(group.pc) + "_" +
                           std::to_string(vi);
                sym.addr = sw.variant_addrs[vi];
                sym.size = chunk.bytes.size();
                sym.isData = false;
                symbols->push_back(sym);
            }
        }
    }

    return image;
}
