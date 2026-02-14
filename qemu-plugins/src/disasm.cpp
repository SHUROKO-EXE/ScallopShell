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

uint64_t cur_pc = 0;
std::atomic<unsigned long> g_exec_ticks = 0;
std::atomic<unsigned long> g_last_pc = 0;

static void write_base_address_file(uint64_t base)
{
    if (base == 0) {
        return;
    }
    static uint64_t last_base = 0;
    if (last_base == base) {
        return;
    }
    const std::filesystem::path path = scallop_base_address_path();
    FILE *f = fopen(path.c_str(), "w");
    if (!f) {
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

/**
 * Disassemble a given qemu instruction with error handling.
 * @param insn Instruction to analyze.
 */
static inline std::string safe_disas(struct qemu_plugin_insn *insn)
{
    const char *s = qemu_plugin_insn_disas(insn);
    std::string disasm = s ? s : "";

    return disasm;
}


static inline uint64_t insn_size_or_zero(struct qemu_plugin_insn *insn)
{
    return qemu_plugin_insn_size(insn);
}

static std::string bytes_to_hex(const uint8_t *data, size_t len)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char b = data[i];
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

/**
 * Identify what type of instruction it is in regards to branching. A Jmp
 * instruction that will always be taken is different than a conditional,
 * which will only sometimes be taken, and it is also different than a regular
 * mov instruction which will go to the fallthrough address every time.
 * @param d Disassembled instruction in std::string form.
 */
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

/**
 * ?????
 */
static int parse_imm_target(const char *d, uint64_t *out_target)
{
    if (!d)
        return 0;
    const char *p = strstr(d, "0x");
    if (!p)
        
    return 0;
    uint64_t v = 0;
    if (sscanf(p, "%lx", &v) == 1)
    {
        *out_target = v;
        return 1;
    }
    if (sscanf(p, "%" SCNx64, out_target) == 1)
        return 1;
    return 0;
}

struct exec_ctx
{
    uint64_t pc, tb_vaddr, fallthrough, branch_target;
    std::string kind;
    std::string disas;
    std::string symbol;
    std::vector<uint8_t> insn_bytes;
};

/**
 * This is the function that outputs branching information to the CSV.
 * @param vcpu_index Which CPU to query 
 * @param udata The exec_ctx which will be logged.
 */
static void log(unsigned int vcpu_index, void *udata)
{

    if (scallopstate.g_resolver.initialized == false) {
        if (!scallopstate.g_resolver.load(qemu_plugin_path_to_binary(), qemu_plugin_start_code())) {
            fprintf(stderr, "SymbolResolver init failed\n");
        }
        scallopstate.g_resolver.initialized = true;
        write_base_address_file(scallop_runtime_base());

    }


    auto *ctx = static_cast<exec_ctx *>(udata);
    if (!ctx || !scallopstate.g_out[vcpu_index]) // If anything failed to initialize, ignore it

    {
        return;
    }

    if (!scallopstate.getGates().isInRange(ctx->pc)) {
        return;
    }

    static int64_t startCode = qemu_plugin_start_code();
    static int64_t endCode = qemu_plugin_end_code();
    if (ctx->pc >= startCode && ctx->pc < startCode + endCode);
    else 
        return;

    SymbolResolver::Hit hit;
    if (scallopstate.g_resolver.lookup(ctx->pc, hit)) {
        ctx->symbol = scallopstate.g_resolver.format_for_display(hit);
    }

    //debug("rip = 0x%" PRIx64 "\n", ctx->pc);
    std::string bytes_hex = ctx->insn_bytes.empty()
                                ? ""
                                : bytes_to_hex(ctx->insn_bytes.data(), ctx->insn_bytes.size());
    int written = 0;
    if (scallopstate.g_log_disas) {
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
    }
    else {
        written = fprintf(scallopstate.g_out[vcpu_index], "0x%" PRIx64 ",%s,%s0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 ",\"%s\"\n",
                          ctx->pc, ctx->kind.c_str(), (ctx->branch_target ? "" : ""), ctx->branch_target ? ctx->branch_target : 0,
                          ctx->fallthrough, ctx->tb_vaddr, bytes_hex.c_str());
    }
    if (written < 0)
    {
        debug("fprintf failed for pc=0x%" PRIx64 ": %s\n", ctx->pc, strerror(errno));
    }
    fflush(scallopstate.g_out[vcpu_index]);

    cur_pc = ctx->pc;

    vcpu_current_thread_index = vcpu_index;
    if (setMem())  debug("failed set mem. \n");
    else debug("> set mem\n");
    if (regDump()) debug("failed regdump.\n");
    else debug("> dumped reg\n");
    if (memDump()) debug("failed memdump.\n");
    else debug("> dumped memory\n");
    
    scallopstate.update();
    scallopstate.getGates().waitIfNeeded(vcpu_index, ctx->pc);
    scallopstate.update();

    debug("TAIL OF LOG\n\n");
}

/**
 * 
 */
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
        ctx->tb_vaddr = tb_va;                  // Virtual address of the block
        auto disas = safe_disas(insn);
        ctx->disas = disas;
        ctx->kind = classify_insn(disas);
        ctx->branch_target = 0;
        uint64_t target;
        if (parse_imm_target(disas.c_str(), &target)) {
            ctx->branch_target = target;
        }
        uint64_t sz = insn_size_or_zero(insn);
        ctx->fallthrough = sz ? ctx->pc + sz : 0;
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

        //const char* sym = qemu_plugin_insn_symbol(insn);
        ctx->symbol = "";

        // Set an instruction callback
        qemu_plugin_register_vcpu_insn_exec_cb(insn, log, QEMU_PLUGIN_CB_RW_REGS, ctx);
    }
}
