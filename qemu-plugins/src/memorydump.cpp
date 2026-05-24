#include "memorydump.hpp"
#include "debug.hpp"
#include <bit>

namespace
{
    std::mutex g_memory_access_log_mutex;
    FILE *g_memory_access_logs[MAX_VCPUS] = {nullptr};

    std::string memory_value_to_hex(const qemu_plugin_mem_value &value)
    {
        char out[35] = {0};
        switch (value.type)
        {
        case QEMU_PLUGIN_MEM_VALUE_U8:
            snprintf(out, sizeof(out), "0x%02" PRIx8, value.data.u8);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U16:
            snprintf(out, sizeof(out), "0x%04" PRIx16, value.data.u16);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U32:
            snprintf(out, sizeof(out), "0x%08" PRIx32, value.data.u32);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U64:
            snprintf(out, sizeof(out), "0x%016" PRIx64, value.data.u64);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U128:
            snprintf(out, sizeof(out), "0x%016" PRIx64 "%016" PRIx64,
                     value.data.u128.high, value.data.u128.low);
            break;
        }
        return out;
    }

    bool should_log_memory_access(uint64_t pc)
    {
        if (!scallopstate.getGates().isInRange(pc))
        {
            return false;
        }

        const uint64_t start_code = qemu_plugin_start_code();
        const uint64_t end_code = qemu_plugin_end_code();
        return pc >= start_code && pc < end_code;
    }
}

/**
 * Print out a hexdump of bytes size N. Space between every byte, every 8 bytes gets a newline.
 * @param f File to save the printout to
 * @param p Pointer to the buffer containing bytes
 * @param n How many bytes to read
 */
static void write_hex_dump(FILE *f, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        fprintf(f, "%02x", p[i]);
        if ((i % 8) == 7)
            fputc('\n', f);
        else
            fputc(' ', f);
    }
    if (n && ((n - 1) % 8) != 7)
        fputc('\n', f);
}

/**
 * Read memory in discrete chunks
 */
static bool try_chunked_memread(uint64_t base, size_t len, GByteArray *buf)
{
    const size_t chunk = 64;
    bool any = false;
    GByteArray *tmp = g_byte_array_sized_new(chunk);
    if (!tmp)
        return false;

    for (size_t off = 0; off < len;)
    {
        size_t want = chunk;
        if (want > len - off)
            want = len - off;

        g_byte_array_set_size(tmp, want);
        if (qemu_plugin_read_memory_vaddr(base + off, tmp, want))
        {
            memcpy(buf->data + off, tmp->data, want);
            any = true;
        }
        else
        {
            memset(buf->data + off, 0, want);
        }
        off += want;
    }

    g_byte_array_free(tmp, TRUE);
    return any;
}

/**
 * Dump memory from the program
 */
int memDump()
{

    debug("memdump started\n");

    // If the command isn't set to Dump Mem, exit.
    if (scallopstate.getIsFlagQueued(vcpu_current_thread_index, VCPU_OP_DUMP_MEM))
    {
        debug("memdump not queued\n");
        return -1;
    }

    // Zero the flag so the request isn't requeued.
    scallopstate.removeFlag(vcpu_current_thread_index, VCPU_OP_DUMP_MEM);

    // Load the address, size N, etc.
    scallop_mem_arguments *memDumpArgs;

    // If arguments fail to load, exit
    if (scallopstate.getArguments<scallop_mem_arguments>(vcpu_current_thread_index, VCPU_OP_DUMP_MEM, &memDumpArgs))
    {
        return 1;
    }

    uint64_t address = memDumpArgs->mem_addr;
    int n = memDumpArgs->mem_size;

    debug("verifying args...");
    // Verify address and size are not null
    if (address == 0)
    {

        return 1;
    }
    if (n == 0)
    {

        return 1;
    }

    debug("verified. \n");
    // Make a GByteArray
    GByteArray *buf = g_byte_array_sized_new(n);
    if (!buf)
    { // If failed to init, return fail

        return 1;
    }

    // Set the size
    g_byte_array_set_size(buf, n);

    // Read the memory
    bool read_ok = qemu_plugin_read_memory_vaddr(address, buf, n);
    if (!read_ok)
    {
        debug("[mem] direct read 0x%016" PRIx64 " +0x%zx failed, retrying in chunks\n",
              address, n);
        read_ok = try_chunked_memread(address, n, buf);
    }

    // If the memory was read correctly:
    if (read_ok)
    {
        // Open the memdump file
        std::filesystem::path path = std::filesystem::temp_directory_path() / ("memdump" + std::to_string(vcpu_current_thread_index) + ".txt");
        FILE *f = fopen(path.c_str(), "w");
        if (f)
        {
            write_hex_dump(f, buf->data, buf->len);
            fclose(f);
            debug("[mem] wrote %zu bytes from 0x%016" PRIx64 " to %s\n",
                  buf->len, address, path);
        }
        else
        {
            debug("it didnt open for some reason???\n");
        }
    }
    else
    {
        debug("[mem] unable to read memory at 0x%016" PRIx64 " len=0x%zx\n",
              address, n);
    }
    g_byte_array_free(buf, TRUE);

    debug("ret from memdump\n");

    return 0;
}

void initMemoryAccessLogs()
{
    std::lock_guard<std::mutex> lock(g_memory_access_log_mutex);

    for (unsigned int i = 0; i < MAX_VCPUS; ++i)
    {
        if (g_memory_access_logs[i])
        {
            fclose(g_memory_access_logs[i]);
            g_memory_access_logs[i] = nullptr;
        }

        const std::filesystem::path path =
            std::filesystem::temp_directory_path() / ("memaccess" + std::to_string(i) + ".txt");
        FILE *f = fopen(path.c_str(), "w+");
        if (!f)
        {
            debug("[memaccess] failed to open %s\n", path.c_str());
            continue;
        }

        setvbuf(f, NULL, _IOLBF, 0);
        fprintf(f, "pc,access,vaddr,size,value,endian,sign_extended\n");
        fflush(f);
        g_memory_access_logs[i] = f;
    }
}

void closeMemoryAccessLogs()
{
    std::lock_guard<std::mutex> lock(g_memory_access_log_mutex);

    for (unsigned int i = 0; i < MAX_VCPUS; ++i)
    {
        if (!g_memory_access_logs[i])
        {
            continue;
        }
        fflush(g_memory_access_logs[i]);
        fclose(g_memory_access_logs[i]);
        g_memory_access_logs[i] = nullptr;
    }
}

void logMemoryAccesses(unsigned int vcpu_index,
                       qemu_plugin_meminfo_t info,
                       uint64_t vaddr,
                       void *userdata)
{
    if (vcpu_index >= MAX_VCPUS || !userdata)
    {
        return;
    }

    const uint64_t pc = *static_cast<const uint64_t *>(userdata);
    if (!should_log_memory_access(pc))
    {
        return;
    }

    const unsigned int size_shift = qemu_plugin_mem_size_shift(info);
    const uint64_t size = size_shift < 64 ? (UINT64_C(1) << size_shift) : 0;
    const char *access = qemu_plugin_mem_is_store(info) ? "write" : "read";
    const char *endian = qemu_plugin_mem_is_big_endian(info) ? "big" : "little";
    const char *sign_extended = qemu_plugin_mem_is_sign_extended(info) ? "true" : "false";
    const std::string value = size_shift <= 4
                                  ? memory_value_to_hex(qemu_plugin_mem_get_value(info))
                                  : "";

    std::lock_guard<std::mutex> lock(g_memory_access_log_mutex);
    FILE *f = g_memory_access_logs[vcpu_index];
    if (!f)
    {
        return;
    }

    fprintf(f, "0x%" PRIx64 ",%s,0x%" PRIx64 ",%" PRIu64 ",%s,%s,%s\n",
            pc, access, vaddr, size, value.c_str(), endian, sign_extended);
    fflush(f);
}
