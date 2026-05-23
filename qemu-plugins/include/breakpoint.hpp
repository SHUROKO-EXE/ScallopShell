#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

enum class BreakpointKind {
    Stop = 1,
    Script = 2,
    Patch = 4,
};

struct BreakpointPatch {
    uint64_t address = 0;
    // If address is non-zero, each pair is {offset, byte}. Otherwise each pair
    // is {absolute_address, byte}.
    std::vector<std::pair<uint64_t, uint8_t>> bytes;
};

struct BreakpointSpec {
    uint64_t address = 0;
    BreakpointKind kind = BreakpointKind::Stop;
    std::string script_path;
    BreakpointPatch patch;
    bool autopatch = false;
    bool stop_after = false;
};

using BreakpointTable = std::vector<BreakpointSpec>;
using BreakpointSnapshot = std::shared_ptr<const BreakpointTable>;

/**
 * Add a breakpoint to the specified address. 
 * @param address Address to break at
 */
int addBreakpoint(uint64_t address);

/**
 * Run a specific function when breakpoint is reached
 * @param breakpoint the breakpoint ID
 * @param func Function to be run
 */
int runFunctionAtBreakpoint(int breakpoint, std::function<int()> func);

/**
 * Run a specific Python script when breakpoint is reached
 * @param breakpoint the breakpoint ID
 * @param scriptPath Script to be run's filepath
 */
int runFunctionAtBreakpoint(int breakpoint, std::string scriptPath);
