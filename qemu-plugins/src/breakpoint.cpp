#include "gate.hpp"
#include "debug.hpp"
#include "main.hpp"

#include <algorithm>
#include <unistd.h>

namespace {
    void write_breakpoints_to_config(unsigned vcpu, const std::vector<uint64_t> &breakpoints) {
        ensure_binary_context_ready();
        ensure_binary_configs_ready();
        if (vcpu >= MAX_VCPUS) {
            return;
        }
        FILE *out = scallopstate.binaryConfigs[vcpu];
        if (!out || out == stderr) {
            debug("[breakpoints] config file not available for vcpu=%u (out=%p)\n", vcpu, (void*)out);
            return;
        }

        int fd = fileno(out);
        if (fd >= 0) {
            ftruncate(fd, 0);
        }
        fseek(out, 0, SEEK_SET);
        fprintf(out, "breakpoint_addr\n");
        const uint64_t base = scallop_runtime_base();
        for (uint64_t addr : breakpoints) {
            uint64_t offset = addr;
            if (base != 0 && addr >= base) {
                offset = addr - base;
            }
            fprintf(out, "0x%llx\n", static_cast<unsigned long long>(offset));
        }
        fflush(out);
        debug("[breakpoints] wrote %zu entries to config for vcpu=%u\n", breakpoints.size(), vcpu);
    }
}


int GateManager::addBreakpoint(uint64_t address, int vcpu) {

    unsigned vcpu_index = vcpu & (MAX_VCPUS - 1);
    gate_t &gate = gateFor(vcpu);
    
    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = std::atomic_load(&gate.bp_vec);
    auto newv = std::make_shared<std::vector<uint64_t>>(oldv ? *oldv : std::vector<uint64_t>{});

    newv->push_back(address);
    std::sort(newv->begin(), newv->end());
    newv->erase(std::unique(newv->begin(), newv->end()), newv->end());

    std::atomic_store(&gate.bp_vec, std::shared_ptr<const std::vector<uint64_t>>(newv));
    write_breakpoints_to_config(vcpu_index, *newv);

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::addBreakpoint(uint64_t address, gate_t& gate) {

    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = std::atomic_load(&gate.bp_vec);
    auto newv = std::make_shared<std::vector<uint64_t>>(oldv ? *oldv : std::vector<uint64_t>{});

    newv->push_back(address);
    std::sort(newv->begin(), newv->end());
    newv->erase(std::unique(newv->begin(), newv->end()), newv->end());

    std::atomic_store(&gate.bp_vec, std::shared_ptr<const std::vector<uint64_t>>(newv));

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::deleteBreakpoint(uint64_t address, int vcpu) {

    unsigned vcpu_index = vcpu & (MAX_VCPUS - 1);
    gate_t &gate = gateFor(vcpu);

    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = std::atomic_load(&gate.bp_vec);
    auto newv = std::make_shared<std::vector<uint64_t>>(oldv ? *oldv : std::vector<uint64_t>{});

    newv->erase(std::remove(newv->begin(), newv->end(), address), newv->end());

    std::atomic_store(&gate.bp_vec, std::shared_ptr<const std::vector<uint64_t>>(newv));
    write_breakpoints_to_config(vcpu_index, *newv);

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::deleteBreakpoint(uint64_t address, gate_t& gate) {

    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = std::atomic_load(&gate.bp_vec);
    auto newv = std::make_shared<std::vector<uint64_t>>(oldv ? *oldv : std::vector<uint64_t>{});

    newv->erase(std::remove(newv->begin(), newv->end(), address), newv->end());

    std::atomic_store(&gate.bp_vec, std::shared_ptr<const std::vector<uint64_t>>(newv));

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::isBreakpoint(uint64_t address, gate_t& gate) {
    auto v = std::atomic_load(&gate.bp_vec);
    if (!v || v->empty()) return 0;
    return std::binary_search(v->begin(), v->end(), address) ? 1 : 0;
}


int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::function<int()> func) {
    return 0;
}

int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::string scriptPath) {
    return 0;
}
