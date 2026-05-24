#pragma once
#include "main.hpp"

int memDump();

void initMemoryAccessLogs();
void closeMemoryAccessLogs();

void logMemoryAccesses(unsigned int vcpu_index,
                       qemu_plugin_meminfo_t info,
                       uint64_t vaddr,
                       void *userdata);
