#include "emulatorAPI.hpp"
#include "fstream"

std::vector<std::string> *Emulator::getRegisters()
{

    static std::filesystem::path kRegDump = std::filesystem::temp_directory_path() / ("regdump" + std::to_string(getSelectedVCPU()) + ".txt");

    static bool tryagain = true;
    static std::vector<std::string> registers;
    static int lastVCPU = getSelectedVCPU();

    bool vcpuChanged = lastVCPU != getSelectedVCPU();

    // Only change filepath when the vcpu changes
    if (vcpuChanged) {
        kRegDump = std::filesystem::temp_directory_path() / ("regdump" + std::to_string(getSelectedVCPU()) + ".txt");
        registers.clear();
        tryagain = true;
    }
    
    lastVCPU = getSelectedVCPU();

    const bool update_requested = getIsFlagQueued(0, VCPU_OP_DUMP_REGS);
    if ((!update_requested && !tryagain))
    {
        return &registers;
    }

    // Request registers (either because a refresh was requested or we're still waiting on a retry)
    std::string cmd = "get registers " + std::to_string(selectedVCPU) + " " + selectedThread + "\n";
    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
    {
        tryagain = true;
        return &registers;
    }

    // Open regdump
    std::ifstream regDump(kRegDump, std::ios::in);
    if (!regDump.is_open())
    {
        tryagain = true;
        return &registers;
    }

    std::vector<std::string> registersTemp;
    std::string line;
    while (std::getline(regDump, line))
    {
        if (!line.empty())
        {
            registersTemp.emplace_back(line);
        }
    }
    regDump.close();

    if (!registersTemp.empty())
    {
        registers = std::move(registersTemp);
        tryagain = false;
        if (update_requested)
        {
            removeFlag(0, VCPU_OP_DUMP_REGS);
        }
    }

    return &registers;
}

int Emulator::setRegister(std::string reg_name, uint64_t value)
{
    (void)reg_name;
    (void)value;
    return 0;
}
