#include "setreg.hpp"

void writeReg()
{

    // Read the registers into a GArray
    GArray *regs = qemu_plugin_get_registers();

    if (regs)
    {
        std::filesystem::path path = *scallopstate.g_reg_path ? scallopstate.g_reg_path : (std::filesystem::temp_directory_path() / "regdump.txt");
        FILE *f = fopen(path.c_str(), "r");

        // If the file was opened correctly
        if (f)
        {
            for (guint i = 0; i < regs->len; i++)
            {
                const uint maxLen = 256;
                // Get the register from the regdump.txt file.
                char *regInFileName = (char *)calloc(maxLen, sizeof(char));
                char *regInFileVal = (char *)calloc(maxLen, sizeof(char));
                fscanf(f, "%s=0x%x", regInFileName, regInFileVal);

                // Black magic. Please figure out later, could be key to optimizing
                qemu_plugin_reg_descriptor *d =
                    &g_array_index(regs, qemu_plugin_reg_descriptor, i);
                if (!d->name)
                    continue;

                // If this isn't the correct register, move on
                if (strncmp(d->name, regInFileName, maxLen) != 0)
                    continue;

                // Read into an empty GByteArray just so you can get the size of the register
                GByteArray *curRegisterValue = g_byte_array_new();
                bool readOk = qemu_plugin_read_register(d->handle, curRegisterValue);
                int registerLength = readOk ? (int)curRegisterValue->len : 0;
 
                GByteArray *newRegisterValue = g_byte_array_new();

                if (registerLength > 0 && (guint)registerLength == curRegisterValue->len)
                {
                    g_byte_array_append(newRegisterValue, (guint8*)regInFileVal, registerLength-1); 
                }

                g_byte_array_free(curRegisterValue, TRUE);
                g_byte_array_free(newRegisterValue, TRUE);
                free(regInFileName);
                free(regInFileVal);
                
            }
            fflush(f);
            int fd = fileno(f);
            if (fd >= 0)
            {
                fsync(fd);
            }
            fclose(f);
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
