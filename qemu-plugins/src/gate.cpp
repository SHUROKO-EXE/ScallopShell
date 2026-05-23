#include "gate.hpp"
#include "debug.hpp"
#include "main.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>

namespace {
    BreakpointKind parseBreakpointKind(const std::string &kind) {
        if (kind == "script") {
            return BreakpointKind::Script;
        }
        if (kind == "patch") {
            return BreakpointKind::Patch;
        }
        return BreakpointKind::Stop;
    }
}

GateManager::GateManager()
    : logging_enabled_(1),
      focus_ranges_(std::make_shared<const std::vector<FocusRange>>()) {
    for (auto &gate : gates_) {
        gate.running.store(1, std::memory_order_relaxed);
        gate.tokens.store(0, std::memory_order_relaxed);
        pthread_mutex_init(&gate.mu, nullptr);
        pthread_cond_init(&gate.cv, nullptr);

        pthread_mutex_init(&gate.bp_write_mu, nullptr);
        gate.bp_vec.store(std::make_shared<const BreakpointTable>(), std::memory_order_release);
    }
    pthread_mutex_init(&focus_write_mu_, nullptr);
}

gate_t &GateManager::gateFor(unsigned vcpu) {
    return gates_[vcpu & (MAX_VCPUS - 1)];
}

void GateManager::initAll() {
    for (auto &gate : gates_) {
        gate.running.store(0, std::memory_order_relaxed);
        gate.tokens.store(0, std::memory_order_relaxed);
    }
}

void GateManager::pauseAll() {
    
    for (auto &gate : gates_) {
        gate.running.store(0, std::memory_order_relaxed);
    }
}

void GateManager::resumeAll() {
    debug("RESUME GM this=%p\n", (void*)this);

    for (auto &gate : gates_) {
        gate.running.store(1, std::memory_order_relaxed);
        pthread_mutex_lock(&gate.mu);
        pthread_cond_broadcast(&gate.cv);
        pthread_mutex_unlock(&gate.mu);
    }
}

void GateManager::give(unsigned vcpu, long tokens) {
    if (tokens <= 0) {
        return;
    }
    gate_t &gate = gateFor(vcpu);
    pthread_mutex_lock(&gate.mu);
    long current = gate.tokens.load(std::memory_order_relaxed);
    gate.tokens.store(current + tokens, std::memory_order_relaxed);
    pthread_cond_broadcast(&gate.cv);
    pthread_mutex_unlock(&gate.mu);
}

void GateManager::stepIfNeeded(unsigned vcpu, uint64_t steps) {
    if (steps == 0) {
        steps = 1; // Default step count
    }
    pauseAll();
    give(vcpu, static_cast<long>(steps));
}

void GateManager::waitIfNeeded(unsigned vcpu, uint64_t pc) {


    gate_t &gate = gateFor(vcpu);

    debug("GM this=%p gate=%p vcpu=%u running=%d\n",
      (void*)this, (void*)&gate, vcpu,
      (int)gate.running.load(std::memory_order_relaxed));


    auto breakpoint = findBreakpoint(pc, gate);
    debug("vcpu = %u", vcpu);
    debug(", %llx = pc,   is break = %d\n",
          static_cast<unsigned long long>(pc),
          breakpoint.has_value() ? 1 : 0);

    const bool hit_breakpoint = breakpoint.has_value();
    if (breakpoint) {
        int action_result = 0;
        switch (breakpoint->kind) {
            case BreakpointKind::Stop:
                pauseAll();
                break;
            case BreakpointKind::Script:
                action_result = runBreakpointScript(*breakpoint, vcpu, pc);
                if (breakpoint->stop_after) pauseAll();
                break;
            case BreakpointKind::Patch:
                action_result = applyBreakpointPatch(*breakpoint);
                if (breakpoint->stop_after) pauseAll();
                break;
        }
        if (action_result != 0) {
            debug("[breakpoints] action failed at pc=0x%llx kind=%d rc=%d\n",
                  static_cast<unsigned long long>(pc),
                  static_cast<int>(breakpoint->kind),
                  action_result);
        }
    }

    if (gate.running.load(std::memory_order_relaxed)) {
        return;
    }

    if (!hit_breakpoint && !isInRange(pc)) {
        return;
    }

    pthread_mutex_lock(&gate.mu);

    for (;;) {
        if (gate.running.load(std::memory_order_relaxed)) {
            break;
        }
        long tokens = gate.tokens.load(std::memory_order_relaxed);
        if (tokens > 0) {
            gate.tokens.fetch_sub(1, std::memory_order_relaxed);
            break;
        }
        pthread_cond_wait(&gate.cv, &gate.mu);
    }

    pthread_mutex_unlock(&gate.mu);
}

void GateManager::inRange(uint64_t lowAddr, uint64_t highAddr) {
    clearFocusRanges();
    if (lowAddr == 0 && highAddr == 0) {
        return;
    }
    addFocusRange(lowAddr, highAddr);
}

bool GateManager::isInRange(uint64_t pc) const {
    auto ranges = std::atomic_load(&focus_ranges_);
    if (!ranges || ranges->empty()) {
        return true;
    }
    for (const auto &range : *ranges) {
        if (pc >= range.lo && pc <= range.hi) {
            return true;
        }
    }
    return false;
}

void GateManager::addFocusRange(uint64_t lowAddr, uint64_t highAddr)
{
    if (highAddr < lowAddr) {
        std::swap(lowAddr, highAddr);
    }

    pthread_mutex_lock(&focus_write_mu_);

    auto oldv = std::atomic_load(&focus_ranges_);
    auto newv = std::make_shared<std::vector<FocusRange>>(oldv ? *oldv : std::vector<FocusRange>{});

    newv->push_back(FocusRange{lowAddr, highAddr});
    std::sort(newv->begin(), newv->end(), [](const FocusRange &a, const FocusRange &b) {
        if (a.lo != b.lo) return a.lo < b.lo;
        return a.hi < b.hi;
    });

    std::vector<FocusRange> merged;
    for (const auto &r : *newv) {
        if (merged.empty() || r.lo > merged.back().hi + 1) {
            merged.push_back(r);
        } else if (r.hi > merged.back().hi) {
            merged.back().hi = r.hi;
        }
    }

    std::atomic_store(&focus_ranges_, std::make_shared<const std::vector<FocusRange>>(std::move(merged)));

    pthread_mutex_unlock(&focus_write_mu_);
}

void GateManager::removeFocusRange(uint64_t lowAddr, uint64_t highAddr)
{
    if (highAddr < lowAddr) {
        std::swap(lowAddr, highAddr);
    }

    pthread_mutex_lock(&focus_write_mu_);

    auto oldv = std::atomic_load(&focus_ranges_);
    std::vector<FocusRange> next;
    if (oldv) {
        for (const auto &r : *oldv) {
            if (highAddr < r.lo || lowAddr > r.hi) {
                next.push_back(r);
                continue;
            }
            if (lowAddr <= r.lo && highAddr >= r.hi) {
                continue;
            }
            if (lowAddr > r.lo && highAddr < r.hi) {
                next.push_back(FocusRange{r.lo, lowAddr - 1});
                next.push_back(FocusRange{highAddr + 1, r.hi});
                continue;
            }
            if (lowAddr <= r.lo && highAddr < r.hi) {
                next.push_back(FocusRange{highAddr + 1, r.hi});
                continue;
            }
            if (lowAddr > r.lo && highAddr >= r.hi) {
                next.push_back(FocusRange{r.lo, lowAddr - 1});
                continue;
            }
        }
    }

    std::atomic_store(&focus_ranges_, std::make_shared<const std::vector<FocusRange>>(std::move(next)));

    pthread_mutex_unlock(&focus_write_mu_);
}

void GateManager::clearFocusRanges()
{
    pthread_mutex_lock(&focus_write_mu_);
    std::atomic_store(&focus_ranges_, std::make_shared<const std::vector<FocusRange>>());
    pthread_mutex_unlock(&focus_write_mu_);
}

void GateManager::setFocusRanges(const std::vector<FocusRange> &ranges)
{
    pthread_mutex_lock(&focus_write_mu_);
    std::vector<FocusRange> sorted = ranges;
    std::sort(sorted.begin(), sorted.end(), [](const FocusRange &a, const FocusRange &b) {
        if (a.lo != b.lo) return a.lo < b.lo;
        return a.hi < b.hi;
    });
    std::vector<FocusRange> merged;
    for (const auto &r : sorted) {
        if (merged.empty() || r.lo > merged.back().hi + 1) {
            merged.push_back(r);
        } else if (r.hi > merged.back().hi) {
            merged.back().hi = r.hi;
        }
    }
    std::atomic_store(&focus_ranges_, std::make_shared<const std::vector<FocusRange>>(std::move(merged)));
    pthread_mutex_unlock(&focus_write_mu_);
}

std::vector<FocusRange> GateManager::getFocusRanges() const
{
    auto ranges = std::atomic_load(&focus_ranges_);
    if (!ranges) {
        return {};
    }
    return *ranges;
}

int GateManager::loadBreakpointsFromFile(unsigned vcpu, FILE *in) {
    if (!in || in == stderr) {
        return -1;
    }

    gate_t &gate = gateFor(vcpu);
    BreakpointTable parsed;
    char line[256];

    if (fseek(in, 0, SEEK_SET) != 0) {
        return -1;
    }

    bool first_line = true;
    while (fgets(line, sizeof(line), in)) {
        std::istringstream iss(line);
        std::string addr_token;
        if (!(iss >> addr_token)) {
            continue;
        }

        if (first_line && addr_token == "breakpoint_addr") {
            first_line = false;
            continue;
        }
        first_line = false;

        char *addr_end = nullptr;
        uint64_t addr = std::strtoull(addr_token.c_str(), &addr_end, 0);
        if (!addr_end || *addr_end != '\0') {
            continue;
        }

        const uint64_t base = scallop_runtime_base();
        BreakpointSpec breakpoint;
        breakpoint.address = base + addr;

        std::string kind;
        int autopatch = 0;
        int stop_after = 0;
        if (iss >> kind) {
            breakpoint.kind = parseBreakpointKind(kind);
        }
        if (iss >> autopatch) {
            breakpoint.autopatch = autopatch != 0;
        }
        if (iss >> stop_after) {
            breakpoint.stop_after = stop_after != 0;
        }
        std::getline(iss >> std::ws, breakpoint.script_path);

        parsed.push_back(breakpoint);
    }

    if (!parsed.empty()) {
        std::sort(parsed.begin(), parsed.end(), [](const BreakpointSpec &lhs, const BreakpointSpec &rhs) {
            return lhs.address < rhs.address;
        });
        parsed.erase(
            std::unique(
                parsed.begin(),
                parsed.end(),
                [](const BreakpointSpec &lhs, const BreakpointSpec &rhs) {
                    return lhs.address == rhs.address;
                }),
            parsed.end());
    }

    pthread_mutex_lock(&gate.bp_write_mu);
    gate.bp_vec.store(std::make_shared<const BreakpointTable>(std::move(parsed)), std::memory_order_release);
    pthread_mutex_unlock(&gate.bp_write_mu);

    return 0;
}
