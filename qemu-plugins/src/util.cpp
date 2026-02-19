#include "util.hpp"

std::string bytes_to_hex(const uint8_t *data, size_t len)
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

static inline std::string safe_disas(struct qemu_plugin_insn *insn)
{
    const char *s = qemu_plugin_insn_disas(insn);
    std::string disasm = s ? s : "";

    return disasm;
}

static int parse_imm_target(const char *d, uint64_t *out_target)
{
    // Null 
    if (!d)
        return 0;

    // Find first occur. of "0x"
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
