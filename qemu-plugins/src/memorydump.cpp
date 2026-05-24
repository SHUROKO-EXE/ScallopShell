#include "memorydump.hpp"
#include "debug.hpp"
#include <bit>

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

    for (size_t off = 0; off < len; )
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
int memDump() {

    debug("memdump started\n");

    // If the command isn't set to Dump Mem, exit. 
    if ( scallopstate.getIsFlagQueued(vcpu_current_thread_index, VCPU_OP_DUMP_MEM)) {
        debug("memdump not queued\n");
        return -1;
    }

    // Zero the flag so the request isn't requeued.
    scallopstate.removeFlag(vcpu_current_thread_index, VCPU_OP_DUMP_MEM);
    
    // Load the address, size N, etc. 
    scallop_mem_arguments* memDumpArgs;

    // If arguments fail to load, exit
    if (scallopstate.getArguments<scallop_mem_arguments>(vcpu_current_thread_index, VCPU_OP_DUMP_MEM, &memDumpArgs)) {
        return 1;        
    }

    uint64_t address = memDumpArgs->mem_addr;
    int n = memDumpArgs->mem_size;

    debug("verifying args...");
    // Verify address and size are not null
    if (address == 0)  {
        
        return 1;
    }
    if (n == 0) { 
        
        return 1;
    }

    debug("verified. \n");
    // Make a GByteArray
    GByteArray *buf = g_byte_array_sized_new(n);
    if (!buf)  {// If failed to init, return fail
        
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
        else {
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

