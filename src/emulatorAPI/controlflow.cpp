#include "emulatorAPI.hpp"

// Static member definitions for selected VCPU and thread
int Emulator::selectedVCPU = 0;
std::string Emulator::selectedThread = "main";

void Emulator::setSelectedVCPU(int vcpu)
{
    selectedVCPU = vcpu;
}

void Emulator::setSelectedThread(const std::string& thread)
{
    selectedThread = thread;
}

int Emulator::getSelectedVCPU()
{
    return selectedVCPU;
}

std::string Emulator::getSelectedThread()
{
    return selectedThread;
}

int Emulator::step(int steps)
{
    if (hasStagedMemoryWrite())
    {
        setFlag(0, VCPU_OP_SET_MEM);
        if (flushStagedMemoryWrite() != 0)
        {
            //fprintf(stderr, "[scallop] failed to stage memory write\n");
            removeFlag(0, VCPU_OP_SET_MEM);
        }
    }

    std::string ret;
    std::string cmd = "step " + std::to_string(steps) + " " +
                      std::to_string(selectedVCPU) + " " + selectedThread;
    bool exitCode = socket.sendCommand(cmd).compare(0, 2, "ok") != 0;
    setFlag(0, VCPU_OP_DUMP_MEM);
    setFlag(0, VCPU_OP_DUMP_REGS);
    setFlag(0, VCPU_OP_SET_REGS);
    getRegisters();
    return exitCode;
}

int Emulator::continueExec()
{
    if (hasStagedMemoryWrite())
    {
        setFlag(0, VCPU_OP_SET_MEM);
        if (flushStagedMemoryWrite() != 0)
        {
            fprintf(stderr, "[scallop] failed to stage memory write\n");
            removeFlag(0, VCPU_OP_SET_MEM);
        }
    }

    std::string ret;
    std::string cmd = "resume " + std::to_string(selectedVCPU) + " " + selectedThread;
    bool exitCode = socket.sendCommand(cmd).compare(0, 2, "ok") != 0;
    setFlag(0, VCPU_OP_DUMP_MEM);
    setFlag(0, VCPU_OP_DUMP_REGS);
    setFlag(0, VCPU_OP_SET_REGS);
    return exitCode;
}

int Emulator::focusMemory(uint64_t lowAddress, uint64_t highAddress)
{
    std::string ret;
    std::string cmd = "focus " + std::to_string(lowAddress) + ';' + std::to_string(highAddress) +
                      " " + std::to_string(selectedVCPU) + " " + selectedThread + '\n';
    std::string exit = socket.sendCommand(cmd);
    return 0;
}

int Emulator::defocusMemory(uint64_t lowAddress, uint64_t highAddress)
{
    std::string ret;
    std::string cmd = "defocus " + std::to_string(lowAddress) + ';' + std::to_string(highAddress) +
                      " " + std::to_string(selectedVCPU) + " " + selectedThread + '\n';
    std::string exit = socket.sendCommand(cmd);
    return 0;
}

int Emulator::getVCPUCount()
{
    // Query backend for VCPU count using fixed parameters
    VCPUInfo info = getVCPUInfo(0, "main");
    if (info.valid && info.vcpus > 0) {
        return info.vcpus;
    }
    // Fallback to 16 if backend query fails
    return 16;
}

std::vector<std::string> Emulator::getVCPUThreadList(int vcpuIndex)
{
    // Query backend for thread count on this VCPU
    VCPUInfo info = getVCPUInfo(vcpuIndex, "main");

    std::vector<std::string> threads;

    if (info.valid && info.threads_per_vcpu > 0) {
        // Generate thread names based on count from backend
        for (int i = 0; i < info.threads_per_vcpu; i++) {
            threads.push_back("thread_" + std::to_string(vcpuIndex) + "_" + std::to_string(i));
        }
        return threads;
    }

    // Fallback to default thread if backend query fails
    return {"thread_" + std::to_string(vcpuIndex) + "_0"};
}

Emulator::VCPUInfo Emulator::getVCPUInfo(int vcpuIndex, const std::string& thread)
{
    VCPUInfo info = {0, 0, 0, false};

    // Build command: get vcpu <vcpu_index> <thread_name>
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "get vcpu %d %.63s\n", vcpuIndex, thread.c_str());

    // Retry up to 5 times if backend isn't ready
    for (int attempt = 0; attempt < 5 && !info.valid; attempt++) {
        if (attempt > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::string response = socket.sendCommand(cmd);

        // Find "vcpu_info" in response
        size_t pos = response.find("vcpu_info");
        if (pos == std::string::npos) {
            continue;  // Retry
        }

        // Parse response: vcpu_info vcpus=%d threads_per_vcpu=%d total_threads=%d
        int vcpus = 0, threads_per_vcpu = 0, total_threads = 0;
        if (std::sscanf(response.c_str() + pos,
                        "vcpu_info vcpus=%d threads_per_vcpu=%d total_threads=%d",
                        &vcpus, &threads_per_vcpu, &total_threads) == 3)
        {
            info.vcpus = vcpus;
            info.threads_per_vcpu = threads_per_vcpu;
            info.total_threads = total_threads;
            info.valid = true;
        }
    }

    return info;
}
