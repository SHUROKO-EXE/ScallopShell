#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <fstream>
#include <vector>
#include "main.hpp"
#include "debug.hpp"
#include "memorydump.hpp"
#include "regdump.hpp"
#include "setmem.hpp"
#include "disasm.hpp"

uint64_t cur_pc = 0;
std::atomic<unsigned long> g_exec_ticks = 0;
std::atomic<unsigned long> g_last_pc = 0;

struct exec_ctx
{
    uint64_t pc, tb_vaddr, fallthrough, branch_target;
    std::string kind;
    std::string disas;
    std::string symbol;
    std::vector<uint8_t> insn_bytes;
};

static void write_base_address_file(uint64_t base)
{
    if (base == 0)
    {
        return;
    }
    static uint64_t last_base = 0;
    if (last_base == base)
    {
        return;
    }
    const std::filesystem::path path = scallop_base_address_path();
    FILE *f = fopen(path.c_str(), "w");
    if (!f)
    {
        debug("[base] failed to open %s\n", path.c_str());
        return;
    }
    fprintf(f, "0x%llx\n", static_cast<unsigned long long>(base));
    fflush(f);
    fclose(f);
    last_base = base;
    debug("[base] wrote runtime base 0x%llx to %s\n",
          static_cast<unsigned long long>(base), path.c_str());
}

static std::string classify_insn(std::string d)
{

    // Handle empty strings
    if (d.empty())
        return "other";

    // Get rid of proceeding spaces and tabs by deleting the first letter until a letter is the first character
    while (d.at(0) == ' ' || d.at(0) == '\t')
        d.erase(0, 1);

    // If after getting rid of spaces and tabs its empty, handle that too
    if (d.empty())
        return "other";

    // The actual classification
    if (!strncmp(d.c_str(), "jmp", 3))
        return "jmp";
    if (d.at(0) == 'j')
        return "cond";
    if (!strncmp(d.c_str(), "call", 4))
        return "call";
    if (!strncmp(d.c_str(), "ret", 3))
        return "ret";
    return "other";
}

static void log(unsigned int vcpu_index, void *udata)
{

    if (scallopstate.g_resolver.initialized == false)
    {

        // Try loading the symbols
        if (!scallopstate.g_resolver.load(qemu_plugin_path_to_binary(), qemu_plugin_start_code()))
        {
            fprintf(stderr, "SymbolResolver init failed\n");
        }

        scallopstate.g_resolver.initialized = true;
        write_base_address_file(scallop_runtime_base());
    }

    auto *ctx = static_cast<exec_ctx *>(udata); // Instruction data

    if (!ctx || !scallopstate.g_out[vcpu_index]) // If anything failed to initialize, ignore it
        return;

    if (!scallopstate.getGates().isInRange(ctx->pc))
    {
        return;
    }

    static int64_t startCode = qemu_plugin_start_code();
    static int64_t endCode = qemu_plugin_end_code();

    // If not in range of the .text segment of target binary, continue.
    if (ctx->pc >= startCode && ctx->pc < startCode + endCode)
        ;
    else
        return;

    // Check if there was a symbol hit.
    SymbolResolver::Hit hit;
    if (scallopstate.g_resolver.lookup(ctx->pc, hit))
    {
        ctx->symbol = scallopstate.g_resolver.format_for_display(hit);
    }

    // debug("rip = 0x%" PRIx64 "\n", ctx->pc);
    std::string bytes_hex = ctx->insn_bytes.empty()
                                ? ""
                                : bytes_to_hex(ctx->insn_bytes.data(), ctx->insn_bytes.size());
    int written = 0;
    written = fprintf(scallopstate.g_out[vcpu_index], "0x%" PRIx64 ",%s,%s0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 ",\"%s\",\"%s\",\"%s\"\n",
                      ctx->pc,
                      ctx->kind.c_str(),
                      (ctx->branch_target ? "" : ""),
                      ctx->branch_target ? ctx->branch_target : 0,
                      ctx->fallthrough,
                      ctx->tb_vaddr,
                      bytes_hex.c_str(),
                      ctx->disas.empty() ? "" : ctx->disas.c_str(),
                      ctx->symbol.c_str());

    if (written < 0)
    {
        debug("fprintf failed for pc=0x%" PRIx64 ": %s\n", ctx->pc, strerror(errno));
    }
    fflush(scallopstate.g_out[vcpu_index]);

    cur_pc = ctx->pc;

    /*
        There is no way to pass in arguments into the command functions,
        so what is currently done is we have a global variable
        (vcpu_current_thread_index) which keeps track of which vcpu called
        log(). Then, because each vCPU callback is in its own thread, the
        command executor functions like regDump() will see the global variable
        as defined in that thread, which will only have one possible
        value: the vCPU index from log.

        This allows the command executor functions to parse the command arguments
        array, making a jank workaround QEMU constraints possible.
    */
    vcpu_current_thread_index = vcpu_index;

    // Handle the command executions. See above
    if (setMem())
        debug("failed set mem. \n");
    else
        debug("> set mem\n");
    if (regDump())
        debug("failed regdump.\n");
    else
        debug("> dumped reg\n");
    if (memDump())
        debug("failed memdump.\n");
    else
        debug("> dumped memory\n");

    scallopstate.update();
    scallopstate.getGates().waitIfNeeded(vcpu_index, ctx->pc);
    scallopstate.update();

    debug("TAIL OF LOG\n\n");
}

void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    ensure_binary_context_ready();
    ensure_binary_configs_ready();

    // Get the translation block virtual address, and the size of it
    uint64_t tb_va = qemu_plugin_tb_vaddr(tb);
    size_t n = qemu_plugin_tb_n_insns(tb);

    // For every instruction in the translated block
    for (size_t i = 0; i < n; i++)
    {

        // Get the i'th instruction in the block, and make its metadata
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        auto *ctx = new exec_ctx();

        ctx->pc = qemu_plugin_insn_vaddr(insn); // Get the virtual address of the instruction

        ctx->tb_vaddr = tb_va; // Virtual address of the block

        auto disas = safe_disas(insn);
        ctx->disas = disas;
        ctx->kind = classify_insn(disas);

        // Branching info
        ctx->branch_target = 0;
        uint64_t target;
        if (parse_imm_target(disas.c_str(), &target))
        {
            ctx->branch_target = target;
        }
        uint64_t sz = static_cast<uint64_t>(qemu_plugin_insn_size(insn));
        ctx->fallthrough = sz ? ctx->pc + sz : 0;

        // Grab the new instruction bytes
        ctx->insn_bytes.clear();
        if (sz > 0)
        {
            ctx->insn_bytes.resize(sz);
            size_t copied = qemu_plugin_insn_data(insn, ctx->insn_bytes.data(), ctx->insn_bytes.size());
            if (copied < ctx->insn_bytes.size())
            {
                ctx->insn_bytes.resize(copied);
            }
        }

        // Default empty symbol
        ctx->symbol = "";

        // Set an instruction callback
        qemu_plugin_register_vcpu_insn_exec_cb(insn, log, QEMU_PLUGIN_CB_RW_REGS, ctx);
    }
}
