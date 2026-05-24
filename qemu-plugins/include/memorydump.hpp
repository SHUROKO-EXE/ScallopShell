#pragma once
#include "main.hpp"

int memDump();

void setMemoryAccessLoggingState(unsigned int vcpu_index, uint64_t pc, bool logged);

void logMemoryAccesses(unsigned int vcpu_index,
                       qemu_plugin_meminfo_t info,
                       uint64_t vaddr,
                       void *userdata);
