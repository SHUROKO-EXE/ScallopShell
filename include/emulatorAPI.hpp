#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <vector>
#include "memory"
#include "string"
#include "functional"
#include "atomic"
#include "socket.hpp"
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include "debug.hpp"
#include <bit>
#include <mutex>
#include <optional>
#include "filesystem"

#include "main.hpp"

/**
 * Enum with commands.
 */
typedef enum : uint64_t {
    VCPU_OP_DUMP_REGS  = 1 << 1,
    VCPU_OP_SET_REGS   = 1 << 2,
    VCPU_OP_DUMP_MEM   = 1 << 3,
    VCPU_OP_SET_MEM    = 1 << 4,
    VCPU_OP_BREAKPOINT = 1 << 5,
} vcpu_operation_t;

static constexpr int MAX_VCPUS = 8;

enum class _EmulType {
    QEMU = 1,
    Gem5 = 2
};

enum class _EmulRetCode {
    SUCCESS = 0,
    ERROR = 1
};

struct InstructionInfo {
    std::string instruction;
    std::string instructionType;
    std::string symbol;
    uint64_t address;
    uint64_t throughAddress;
    uint64_t fallThroughAddress;
    uint8_t addrTaken;

    InstructionInfo(std::string _instruction, 
        std::string _instructionType,
        std::string _symbol,
        uint64_t _address,
        uint64_t _throughAddress,
        uint64_t _fallThroughAddress,
        uint8_t _addrTaken) {

            instruction = std::move(_instruction);
            instructionType = std::move(_instructionType);
            symbol = std::move(_symbol);
            address = std::move(_address);
            throughAddress = std::move(_throughAddress);
            fallThroughAddress = std::move(_fallThroughAddress);
            addrTaken = std::move(_addrTaken);
    }
};

// The class containing the emulator scallop shell runs
class Emulator {
private:

    std::string binaryPath;
    static bool isEmulating;

    static PluginNetwork socket;

    static std::atomic_uint64_t flags[MAX_VCPUS];

    static int selectedVCPU;
    static std::string selectedThread;
    static std::string binaryStem;

public:

    static int setFlag(int vcpu, vcpu_operation_t cmd);

    static int removeFlag(int vcpu, vcpu_operation_t cmd);

    static bool getIsFlagQueued(int vcpu, vcpu_operation_t cmd);
    /**
     * Start emulating. Currently, QEMU is the only compatible emulator.
     */
    static int startEmulation(const std::string& executablePath, const std::string& arch, bool system = false);

    static int addBreakpoint(uint64_t address, std::string& comment);
    static int deleteBreakpoint(uint64_t address);
    static std::filesystem::path getBreakpointConfigPath(int vcpuIndex = -1);
    static std::vector<uint64_t> getBreakpointsFromConfig(int vcpuIndex = -1);

    /**
     * Modify the memory from the address given until the address + n. 
     */
    static int modifyMemory(uint64_t address, uint8_t* data, int n);

    /**
     * Modify the memory from the address given until the address + n. 
     */
    static int modifyMemory(uint64_t address, std::vector<uint8_t>* data, int n);

    /**
     * Stage edits so they can be flushed the next time execution advances.
     */
    static void stageMemoryWrite(uint64_t address, const std::vector<uint8_t>& data, int n);
    static bool hasStagedMemoryWrite();
    static int flushStagedMemoryWrite();

    static int focusMemory(uint64_t lowAddress, uint64_t highAddress);

    /**
     * Retrieve memory from an address
     */
    static std::vector<uint8_t>* getMemory(uint64_t address, int n,
                                           int targetMods = 1, const std::string& cacheKey = std::string());

    /**
     * Get the registers
     */
    static std::vector<std::string>* getRegisters();

    /**
     * Set the value of a register
     */
    static int setRegister(std::string registerName, uint64_t value);

    static std::shared_ptr<std::pair<uint64_t, uint64_t>> getInstructionJumpPaths(uint64_t address);
    
    static int step(int steps = 1);

    static int continueExec();

    static std::string disassembleInstruction(uint64_t address, std::shared_ptr<uint8_t> data, int n = 16);

    static std::vector<InstructionInfo>* getRunInstructions(int line, int n, bool* updated, int* total_lines_out);

    static bool getIsEmulating();

    /**
     * Get the file descriptor for reading QEMU's stdout/stderr output.
     * Returns -1 if not available.
     */
    static int getOutputFd();

    /**
     * Get the file descriptor for writing to QEMU's stdin.
     * Returns -1 if not available.
     */
    static int getInputFd();

    /**
     * Get the child process PID (QEMU subprocess).
     * Returns -1 if no child process is running.
     */
    static pid_t getChildPid();

    /**
     * Get the number of virtual CPUs.
     * Returns the count of VCPUs available in the emulator.
     */
    static int getVCPUCount();

    /**
     * Get the list of threads for a specific VCPU.
     * Returns thread names/identifiers for the given CPU.
     */
    static std::vector<std::string> getVCPUThreadList(int vcpuIndex);

    /**
     * VCPU info structure returned by getVCPUInfo.
     */
    struct VCPUInfo {
        int vcpus;
        int threads_per_vcpu;
        int total_threads;
        bool valid;
    };

    /**
     * Query VCPU info from the backend for a specific VCPU and thread.
     * Sends: get vcpu <vcpu_index> <thread_name>
     * Parses response: vcpu_info vcpus=%d threads_per_vcpu=%d total_threads=%d
     */
    static VCPUInfo getVCPUInfo(int vcpuIndex, const std::string& thread);

    /**
     * Set the currently selected VCPU and thread for commands.
     */
    static void setSelectedVCPU(int vcpu);
    static void setSelectedThread(const std::string& thread);

    /**
     * Get the currently selected VCPU and thread.
     */
    static int getSelectedVCPU();
    static std::string getSelectedThread();

};
