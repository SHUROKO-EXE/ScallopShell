#include "main.hpp"
#include "boxedHandlerGenerator.hpp"
#include <algorithm>
#include <unordered_map>
#include <stdexcept>
#include <capstone/capstone.h>

// Rewrites all rel8 jump/call immediates to rel32 so that relocateX64Chunk
// never has to change instruction sizes (no size-mismatch with NOP placeholders).
static std::vector<uint8_t> promoteRel8ToRel32(const std::vector<uint8_t>& bytes,
                                               uint64_t pc) {
    if (bytes.empty())
        return bytes;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return bytes;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, bytes.data(), bytes.size(), pc, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        return bytes;
    }

    std::vector<uint8_t> out;
    out.reserve(bytes.size() + count * 4);
    int64_t sizeAdjust = 0;

    for (size_t i = 0; i < count; ++i) {
        const cs_insn& ci = insn[i];
        if (!ci.detail) {
            out.insert(out.end(), ci.bytes, ci.bytes + ci.size);
            continue;
        }
        const cs_x86& x86 = ci.detail->x86;

        if ((cs_insn_group(handle, &ci, CS_GRP_JUMP) ||
             cs_insn_group(handle, &ci, CS_GRP_CALL)) &&
            x86.op_count > 0 &&
            x86.operands[0].type == X86_OP_IMM &&
            x86.encoding.imm_size == 1) {

            // Address of this instruction in the growing output
            const uint64_t curAddr =
                ci.address + static_cast<uint64_t>(sizeAdjust);
            const int64_t target = static_cast<int64_t>(x86.operands[0].imm);
            const uint8_t op =
                bytes[static_cast<size_t>(ci.address - pc)];

            if (op == 0xEB) {
                // jmp short (2 bytes) → jmp near (5 bytes)
                const uint32_t v =
                    static_cast<uint32_t>(target - static_cast<int64_t>(curAddr + 5));
                out.push_back(0xE9);
                out.push_back(v & 0xFF);
                out.push_back((v >> 8) & 0xFF);
                out.push_back((v >> 16) & 0xFF);
                out.push_back((v >> 24) & 0xFF);
                sizeAdjust += 3;
            } else if (op >= 0x70 && op <= 0x7F) {
                // jcc short (2 bytes) → jcc near (6 bytes: 0F 8x + rel32)
                const uint32_t v =
                    static_cast<uint32_t>(target - static_cast<int64_t>(curAddr + 6));
                out.push_back(0x0F);
                out.push_back(static_cast<uint8_t>(0x80 | (op - 0x70)));
                out.push_back(v & 0xFF);
                out.push_back((v >> 8) & 0xFF);
                out.push_back((v >> 16) & 0xFF);
                out.push_back((v >> 24) & 0xFF);
                sizeAdjust += 4;
            } else {
                // Unknown rel8 form — leave as-is; relocateX64Chunk will catch it.
                out.insert(out.end(), ci.bytes, ci.bytes + ci.size);
            }
        } else {
            out.insert(out.end(), ci.bytes, ci.bytes + ci.size);
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
    return out;
}

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
            if (x86.encoding.imm_size == 1)
                throw std::runtime_error(
                    "rel8 in variant chunk after pre-normalization (bug in promoteRel8ToRel32)");
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

            // Use only the observed instruction bytes — no padding.
            // Padding to 5 bytes would pull in bytes from the next instruction,
            // creating spurious variant groups at intermediate PCs and causing
            // overlapping 5-byte stubs to corrupt each other's displacements.
            VariantChunk chunk{insn.pc, promoteRel8ToRel32(insn.bytes, insn.pc)};
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
                throw std::runtime_error("targetTriple is required for boxed handler stubs");
            }
        }
    }

    struct SwitcherLayout {
        uint64_t pc;
        std::vector<VariantChunk> variants;
        uint64_t counter_addr = 0;
        uint64_t stub_addr = 0;
        std::vector<uint8_t> stub_bytes;
    };

    std::vector<SwitcherLayout> boxedHandlers;
    boxedHandlers.reserve(groups.size());

    for (const auto& group : groups) {
        if (group.variants.size() <= 1)
            continue;

        SwitcherLayout layout;
        layout.pc = group.pc;
        layout.variants = group.variants;
        boxedHandlers.push_back(std::move(layout));
    }

    auto alignUp = [](uint64_t value, uint64_t align) {
        return (value + align - 1) & ~(align - 1);
    };

    uint64_t counters_base = alignUp(max_end, 8);
    for (size_t i = 0; i < boxedHandlers.size(); ++i) {
        boxedHandlers[i].counter_addr = counters_base + i * 8;
    }

    const uint64_t counters_end = counters_base + boxedHandlers.size() * 8;
    uint64_t stub_cursor = counters_end;
    for (auto& bh : boxedHandlers) {
        bh.stub_addr = stub_cursor;
        // continuationAddr: byte immediately after the 5-byte stub jmp in .text.
        // Variant bytes that fall through need to jump here after executing.
        bh.stub_bytes = emitBoxedHandler(targetTriple, bh.stub_addr, bh.counter_addr,
                                         bh.variants, bh.pc + 5);
        stub_cursor += bh.stub_bytes.size();
    }
    const uint64_t final_end = stub_cursor;

    if (dataStart)
        *dataStart = counters_base;
    if (dataEnd)
        *dataEnd = counters_end;

    const uint64_t size = final_end - min_pc;
    std::vector<uint8_t> image(static_cast<size_t>(size), pad);
    std::vector<uint8_t> occupied(static_cast<size_t>(original_size), 0);

    // Place full boxed handler logic out-of-line and only patch a near jump at the
    // original PC to keep reconstructed code layout close to the original.
    for (const auto& sw : boxedHandlers) {
        const uint64_t stub_off = sw.stub_addr - min_pc;
        if (stub_off + sw.stub_bytes.size() > image.size())
            continue;
        std::copy(sw.stub_bytes.begin(), sw.stub_bytes.end(),
                  image.begin() + static_cast<size_t>(stub_off));

        const uint64_t off = sw.pc - min_pc;
        if (off + 5 > image.size())
            continue;
        // Skip if this PC is already inside a previously-written stub.
        // Without this, stubs at consecutive PCs overwrite each other's
        // displacement bytes.
        if (off < occupied.size() && occupied[static_cast<size_t>(off)])
            continue;

        const int64_t rel =
            static_cast<int64_t>(sw.stub_addr) - static_cast<int64_t>(sw.pc + 5);
        if (rel < INT32_MIN || rel > INT32_MAX) {
            std::cerr << "Warning: boxed handler jump out of range at pc=0x"
                      << std::hex << sw.pc << " -> 0x" << sw.stub_addr
                      << std::dec << " (boxed handler skipped)" << std::endl;
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

    for (const auto& sw : boxedHandlers) {
        const uint64_t counter_off = sw.counter_addr - min_pc;
        if (counter_off + 8 <= image.size()) {
            for (size_t i = 0; i < 8; ++i) {
                image[static_cast<size_t>(counter_off + i)] = 0;
            }
        }
    }

    // Only export the boxed-handler bodies. The 5-byte trampolines at the
    // original PCs and the counter slots are implementation details and cause
    // noisy synthetic functions in Binary Ninja.
    if (symbols) {
        symbols->clear();
        for (const auto& sw : boxedHandlers) {
            ElfSymbol body{};
            body.name = "switcher_body_" + std::to_string(sw.pc);
            body.addr = sw.stub_addr;
            body.size = sw.stub_bytes.size();
            body.isData = false;
            symbols->push_back(body);
        }
    }

    return image;
}
