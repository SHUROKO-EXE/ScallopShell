#pragma once
#include <atomic>
#include <cstdint>
#include <pthread.h>
#include <stdio.h>
#include <vector>
#include "functional"
#include "string"
#include "unordered_map"
#include "memory"

constexpr unsigned MAX_VCPUS = 64;

struct gate_t {
    std::atomic<int> running;   /* 1 = free-run, 0 = gated */
    std::atomic<long> tokens;   /* available instruction credits */
    pthread_mutex_t mu;
    pthread_cond_t cv;
    
    std::shared_ptr<const std::vector<uint64_t>> bp_vec; // accessed atomically via atomic_load/store
    pthread_mutex_t bp_write_mu; // serialize writers 
};

struct FocusRange {
    uint64_t lo = 0;
    uint64_t hi = 0;
};

class GateManager {
public:
    GateManager();

    void initAll();
    void pauseAll();
    void resumeAll();
    void stepIfNeeded(unsigned vcpu, uint64_t steps);
    void waitIfNeeded(unsigned vcpu, uint64_t pc);
    void inRange(uint64_t lowAddr, uint64_t highAddr);
    bool isInRange(uint64_t pc) const;
    void addFocusRange(uint64_t lowAddr, uint64_t highAddr);
    void removeFocusRange(uint64_t lowAddr, uint64_t highAddr);
    void clearFocusRanges();
    void setFocusRanges(const std::vector<FocusRange> &ranges);
    std::vector<FocusRange> getFocusRanges() const;

    void give(unsigned vcpu, long tokens);

    bool loggingEnabled() const { return logging_enabled_.load(std::memory_order_relaxed) != 0; }
    void setLoggingEnabled(bool enable) { logging_enabled_.store(enable ? 1 : 0, std::memory_order_relaxed); }

    /**
     * Add a breakpoint to the specified address. 
     * @param address Address to break at
     */
    int addBreakpoint(uint64_t address, gate_t& gate);

    /**
     * Add a breakpoint to the specified address. 
     * @param address Address to break at
     */
    int addBreakpoint(uint64_t address, int vcpu);

    /**
     * Remove a breakpoint from the specified address.
     * @param address Address to remove
     */
    int deleteBreakpoint(uint64_t address, gate_t& gate);

    /**
     * Remove a breakpoint from the specified address.
     * @param address Address to remove
     */
    int deleteBreakpoint(uint64_t address, int vcpu);
    
    /**
     * Checks if there's a breakpoint at the specified address
     */
    int isBreakpoint(uint64_t address, gate_t& gate);

    /**
     * Run a specific function when breakpoint is reached
     * @param breakpoint the breakpoint ID
     * @param func Function to be run
     */
    int runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::function<int()> func);

    /**
     * Run a specific Python script when breakpoint is reached
     * @param breakpoint the breakpoint ID
     * @param scriptPath Script to be run's filepath
     */
    int runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::string scriptPath);

    /**
     * Load breakpoints from a config file without rewriting it.
     * @param vcpu VCPU index to update
     * @param in Opened config file
     */
    int loadBreakpointsFromFile(unsigned vcpu, FILE *in);

protected:
    gate_t gates_[MAX_VCPUS];
    std::atomic<int> logging_enabled_;
    std::atomic<std::shared_ptr<const std::vector<FocusRange>>> focus_ranges_;
    pthread_mutex_t focus_write_mu_;

    gate_t &gateFor(unsigned vcpu);
};
