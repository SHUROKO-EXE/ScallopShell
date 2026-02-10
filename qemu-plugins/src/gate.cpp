#include "gate.hpp"
#include "debug.hpp"
#include "main.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

GateManager::GateManager()
    : logging_enabled_(1),
      focus_ranges_(std::make_shared<const std::vector<FocusRange>>()) {
    for (auto &gate : gates_) {
        gate.running.store(1, std::memory_order_relaxed);
        gate.tokens.store(0, std::memory_order_relaxed);
        pthread_mutex_init(&gate.mu, nullptr);
        pthread_cond_init(&gate.cv, nullptr);

        pthread_mutex_init(&gate.bp_write_mu, nullptr);
        std::atomic_store(&gate.bp_vec, std::make_shared<const std::vector<uint64_t>>());


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


    debug("vcpu = %d", vcpu);
    debug(", %llx = pc,   is break = %d\n", pc, isBreakpoint(pc, gate));
    if (isBreakpoint(pc, gate)) {
        /*for (;;) {
            if (gate.running.load(std::memory_order_relaxed)) {
                break;
            }
            long tokens = gate.tokens.load(std::memory_order_relaxed);
            if (tokens > 0) {
                gate.tokens.fetch_sub(1, std::memory_order_relaxed);
                break;
            }
            pthread_cond_wait(&gate.cv, &gate.mu);
        }*/
        debug("8490482309483290432904324u320942\n");
        pauseAll();
    
        //return;
    }

    if (gate.running.load(std::memory_order_relaxed)) {
        return;
    }

    if (!isInRange(pc)) {
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
    std::vector<uint64_t> parsed;
    char line[256];

    if (fseek(in, 0, SEEK_SET) != 0) {
        return -1;
    }

    bool first_line = true;
    while (fgets(line, sizeof(line), in)) {
        if (first_line) {
            first_line = false;
            if (strncmp(line, "breakpoint_addr", 15) == 0) {
                continue;
            }
        }

        char *p = line;
        while (*p && std::isspace(static_cast<unsigned char>(*p))) {
            ++p;
        }
        if (*p == '\0') {
            continue;
        }

        char *end = nullptr;
        uint64_t addr = std::strtoull(p, &end, 0);
        if (!end || end == p) {
            continue;
        }
        const uint64_t base = scallop_runtime_base();
        parsed.push_back(base + addr);
    }

    if (!parsed.empty()) {
        std::sort(parsed.begin(), parsed.end());
        parsed.erase(std::unique(parsed.begin(), parsed.end()), parsed.end());
    }

    pthread_mutex_lock(&gate.bp_write_mu);
    std::atomic_store(&gate.bp_vec, std::make_shared<const std::vector<uint64_t>>(std::move(parsed)));
    pthread_mutex_unlock(&gate.bp_write_mu);

    return 0;
}
