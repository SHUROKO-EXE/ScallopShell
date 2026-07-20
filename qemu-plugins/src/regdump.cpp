#include "regdump.hpp"
#include "debug.hpp"

int regDump()
{
    //debug("STARTED REGDUMP\n");
    // Reg Dump flag is not set, return
    if (scallopstate.getIsFlagQueued(vcpu_current_thread_index, VCPU_OP_DUMP_REGS)) {
        return -1;
    }

    // Clear the get register flag
    scallopstate.removeFlag(vcpu_current_thread_index, VCPU_OP_DUMP_REGS);

    GArray *regs = qemu_plugin_get_registers();
    
    if (regs)
    {
        //debug("got registers\n");
        
        std::filesystem::path path = std::filesystem::temp_directory_path() / ("regdump" + std::to_string(vcpu_current_thread_index) + ".txt");
        FILE *f = fopen(path.c_str(), "w");

        if (f)
        {
            
            for (guint i = 0; i < regs->len; i++)
            {
                qemu_plugin_reg_descriptor *d =
                    &g_array_index(regs, qemu_plugin_reg_descriptor, i);
                if (!d->name)
                    continue;

                // Read into an empty GByteArray so QEMU sets the true size.
                GByteArray *val = g_byte_array_new();
                bool read_ok = qemu_plugin_read_register(d->handle, val);
                int got = read_ok ? (int)val->len : 0;

                if (got > 0 && (guint)got == val->len)
                {
                    // If it's a program counter, do it differently. please change later, this is a hack
                    if (!strncmp(d->name, "rip", 3) || !strncmp(d->name, "eip", 3)) {
                        fprintf(f, "%s=0x%llx", d->name, cur_pc);
                        fputc('\n', f);
                        continue;
                    }
                    fprintf(f, "%s=0x", d->name);
                    for (int j = got - 1; j >= 0; j--)
                        fprintf(f, "%02x", val->data[j]);
                    fputc('\n', f);
                }
                g_byte_array_free(val, TRUE);
            }
            fflush(f);
            int fd = fileno(f);
            if (fd >= 0)
            {
                fsync(fd);
            }
            fclose(f);
        }
        g_array_free(regs, TRUE);
    }

    return 0;
}
