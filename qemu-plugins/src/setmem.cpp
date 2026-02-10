#include "setmem.hpp"
#include "debug.hpp"

int setMem() {
    
    // If the command isn't set to Dump Mem, exit. 
    if (scallopstate.getIsFlagQueued(vcpu_current_thread_index, VCPU_OP_SET_MEM)) {
        return -1;
    }

    // Zero the flag so the request isn't requeued.
    scallopstate.removeFlag(vcpu_current_thread_index, VCPU_OP_SET_MEM);
    
    // Load the address, size N, etc. 
    scallop_mem_arguments* memDumpArgs;

    // If arguments fail to load, exit
    if (scallopstate.getArguments<scallop_mem_arguments>(vcpu_current_thread_index, VCPU_OP_SET_MEM, &memDumpArgs)) {
        debug("failed to load arguments\n");
        return 1;        
    }

    uint64_t address = memDumpArgs->mem_addr;
    int n = memDumpArgs->mem_size;
    debug("loaded arguments\n");

    // Verify address and size are not null
    if (address == 0)  {
        
        return 1;
    }
    if (n == 0) { 
        
        return 1;
    }

    debug("verified args\n");

    // Make a GByteArray
    GByteArray *buf = g_byte_array_sized_new(n);
    if (!buf)  {// If failed to init, return fail
        debug("Bad GByteArray\n");
        return 1;
    }

    // Open memdump
    std::filesystem::path path = *scallopstate.g_mem_path ? scallopstate.g_mem_path : (std::filesystem::temp_directory_path() / "memdump.txt");
    FILE *f = fopen(path.c_str(), "r");
    if (f)
    {
        // Scan the file byte by byte, but never write more than requested.
        uint8_t byteFromFile = 0;
        size_t bytes_read = 0;
        while (bytes_read < static_cast<size_t>(n) &&
               fscanf(f, " %hhx", &byteFromFile) == 1)
        {
            g_byte_array_append(buf, &byteFromFile, 1);
            bytes_read++;
        }
        if (bytes_read < static_cast<size_t>(n))
        {
            debug("[setmem] short read: wanted %d bytes, got %zu\n", n, bytes_read);
        }
        fclose(f);
    }
    else
    {
        debug("Couldn't open \n");
    }    

    // ---------
    // Write the memory
    bool write_ok = qemu_plugin_write_memory_vaddr(address, buf);
    if (!write_ok)
    {
        debug(" set mem failed!!! %llx->%llx    %d --- %d\n", address, address - buf->len, buf->len, n);
    }

    g_byte_array_free(buf, TRUE);

    return 0;
}
