#include "gate.hpp"
#include "debug.hpp"
#include "main.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace {
    struct ProcessResult {
        bool started = false;
        int exit_code = -1;
        int error_code = 0;
    };

    const char *breakpoint_kind_name(BreakpointKind kind) {
        switch (kind) {
            case BreakpointKind::Stop:
                return "stop";
            case BreakpointKind::Script:
                return "script";
            case BreakpointKind::Patch:
                return "patch";
        }
        return "stop";
    }

    int truncate_file(FILE *out) {
#if defined(_WIN32)
        int fd = _fileno(out);
        if (fd < 0) {
            return -1;
        }
        return _chsize_s(fd, 0) == 0 ? 0 : -1;
#else
        int fd = fileno(out);
        if (fd < 0) {
            return -1;
        }
        return ftruncate(fd, 0);
#endif
    }

#if !defined(_WIN32)
    void log_child_exit(pid_t pid, std::string command, std::string script_path) {
        std::thread([pid, command = std::move(command), script_path = std::move(script_path)]() {
            int status = 0;
            while (waitpid(pid, &status, 0) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                debug("[breakpoints] failed while waiting for script %s via %s: %s\n",
                      script_path.c_str(),
                      command.c_str(),
                      std::strerror(errno));
                return;
            }

            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                if (exit_code == 0) {
                    debug("[breakpoints] script %s completed via %s\n",
                          script_path.c_str(),
                          command.c_str());
                } else {
                    debug("[breakpoints] script %s exited with code %d via %s\n",
                          script_path.c_str(),
                          exit_code,
                          command.c_str());
                }
                return;
            }

            if (WIFSIGNALED(status)) {
                debug("[breakpoints] script %s terminated by signal %d via %s\n",
                      script_path.c_str(),
                      WTERMSIG(status),
                      command.c_str());
            }
        }).detach();
    }
#endif

    ProcessResult run_process(const std::vector<std::string> &argv) {
        if (argv.empty()) {
            return {};
        }

        std::vector<char *> raw_argv;
        raw_argv.reserve(argv.size() + 1);
        for (const std::string &arg : argv) {
            raw_argv.push_back(const_cast<char *>(arg.c_str()));
        }
        raw_argv.push_back(nullptr);

#if defined(_WIN32)
        intptr_t process = _spawnvp(_P_NOWAIT, raw_argv[0], raw_argv.data());
        if (process == -1) {
            return ProcessResult{false, -1, errno};
        }
        CloseHandle(reinterpret_cast<HANDLE>(process));
        return ProcessResult{true, 0, 0};
#else
        pid_t pid = -1;
        int spawn_rc = posix_spawnp(&pid, raw_argv[0], nullptr, nullptr, raw_argv.data(), environ);
        if (spawn_rc != 0) {
            return ProcessResult{false, -1, spawn_rc};
        }
        log_child_exit(pid, argv[0], argv.size() > 1 ? argv[1] : "");
        return ProcessResult{true, 0, 0};
#endif
    }

    std::vector<std::vector<std::string>> python_command_candidates(
        const std::string &script_path,
        const std::string &pc_arg,
        const std::string &vcpu_arg) {
        std::vector<std::vector<std::string>> candidates;

        const char *configured_python = std::getenv("SCALLOP_PYTHON");
        if (configured_python && *configured_python) {
            candidates.push_back({configured_python, script_path, pc_arg, vcpu_arg});
        }

#if defined(_WIN32)
        candidates.push_back({"py", "-3", script_path, pc_arg, vcpu_arg});
        candidates.push_back({"python", script_path, pc_arg, vcpu_arg});
#else
        candidates.push_back({"python3", script_path, pc_arg, vcpu_arg});
        candidates.push_back({"python", script_path, pc_arg, vcpu_arg});
#endif

        return candidates;
    }

    BreakpointSpec stop_breakpoint(uint64_t address) {
        BreakpointSpec breakpoint;
        breakpoint.address = address;
        breakpoint.kind = BreakpointKind::Stop;
        return breakpoint;
    }

    bool breakpoint_address_less(const BreakpointSpec &lhs, const BreakpointSpec &rhs) {
        return lhs.address < rhs.address;
    }

    void sort_unique_breakpoints(BreakpointTable &breakpoints) {
        std::sort(breakpoints.begin(), breakpoints.end(), breakpoint_address_less);
        breakpoints.erase(
            std::unique(
                breakpoints.begin(),
                breakpoints.end(),
                [](const BreakpointSpec &lhs, const BreakpointSpec &rhs) {
                    return lhs.address == rhs.address;
                }),
            breakpoints.end());
    }

    BreakpointTable copy_breakpoint_table(const BreakpointSnapshot &snapshot) {
        return snapshot ? *snapshot : BreakpointTable{};
    }

    void write_breakpoints_to_config(unsigned vcpu, const BreakpointTable &breakpoints) {
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

        if (truncate_file(out) != 0) {
            debug("[breakpoints] failed to truncate config for vcpu=%u\n", vcpu);
        }
        fseek(out, 0, SEEK_SET);
        fprintf(out, "breakpoint_addr kind autopatch stop_after script_path\n");
        const uint64_t base = scallop_runtime_base();
        for (const BreakpointSpec &breakpoint : breakpoints) {
            uint64_t offset = breakpoint.address;
            if (base != 0 && breakpoint.address >= base) {
                offset = breakpoint.address - base;
            }
            fprintf(out,
                    "0x%llx %s %d %d %s\n",
                    static_cast<unsigned long long>(offset),
                    breakpoint_kind_name(breakpoint.kind),
                    breakpoint.autopatch ? 1 : 0,
                    breakpoint.stop_after ? 1 : 0,
                    breakpoint.script_path.c_str());
        }
        fflush(out);
        debug("[breakpoints] wrote %zu entries to config for vcpu=%u\n", breakpoints.size(), vcpu);
    }
}


int GateManager::addBreakpoint(uint64_t address, int vcpu) {
    return addBreakpoint(stop_breakpoint(address), vcpu);
}

int GateManager::addBreakpoint(const BreakpointSpec &breakpoint, int vcpu) {
    unsigned vcpu_index = vcpu & (MAX_VCPUS - 1);
    gate_t &gate = gateFor(vcpu);
    
    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = gate.bp_vec.load(std::memory_order_acquire);
    auto newv = std::make_shared<BreakpointTable>(copy_breakpoint_table(oldv));

    newv->erase(
        std::remove_if(
            newv->begin(),
            newv->end(),
            [&breakpoint](const BreakpointSpec &existing) {
                return existing.address == breakpoint.address;
            }),
        newv->end());
    newv->push_back(breakpoint);
    sort_unique_breakpoints(*newv);

    gate.bp_vec.store(BreakpointSnapshot(newv), std::memory_order_release);
    write_breakpoints_to_config(vcpu_index, *newv);

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::addBreakpoint(uint64_t address, gate_t& gate) {
    return addBreakpoint(stop_breakpoint(address), gate);
}

int GateManager::addBreakpoint(const BreakpointSpec &breakpoint, gate_t& gate) {
    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = gate.bp_vec.load(std::memory_order_acquire);
    auto newv = std::make_shared<BreakpointTable>(copy_breakpoint_table(oldv));

    newv->erase(
        std::remove_if(
            newv->begin(),
            newv->end(),
            [&breakpoint](const BreakpointSpec &existing) {
                return existing.address == breakpoint.address;
            }),
        newv->end());
    newv->push_back(breakpoint);
    sort_unique_breakpoints(*newv);

    gate.bp_vec.store(BreakpointSnapshot(newv), std::memory_order_release);

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::deleteBreakpoint(uint64_t address, int vcpu) {

    unsigned vcpu_index = vcpu & (MAX_VCPUS - 1);
    gate_t &gate = gateFor(vcpu);

    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = gate.bp_vec.load(std::memory_order_acquire);
    auto newv = std::make_shared<BreakpointTable>(copy_breakpoint_table(oldv));

    newv->erase(
        std::remove_if(
            newv->begin(),
            newv->end(),
            [address](const BreakpointSpec &breakpoint) {
                return breakpoint.address == address;
            }),
        newv->end());

    gate.bp_vec.store(BreakpointSnapshot(newv), std::memory_order_release);
    write_breakpoints_to_config(vcpu_index, *newv);

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::deleteBreakpoint(uint64_t address, gate_t& gate) {

    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = gate.bp_vec.load(std::memory_order_acquire);
    auto newv = std::make_shared<BreakpointTable>(copy_breakpoint_table(oldv));

    newv->erase(
        std::remove_if(
            newv->begin(),
            newv->end(),
            [address](const BreakpointSpec &breakpoint) {
                return breakpoint.address == address;
            }),
        newv->end());

    gate.bp_vec.store(BreakpointSnapshot(newv), std::memory_order_release);

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

std::optional<BreakpointSpec> GateManager::findBreakpoint(uint64_t address, gate_t& gate) {
    auto table = gate.bp_vec.load(std::memory_order_acquire);
    if (!table) return std::nullopt;

    auto it = std::lower_bound(table->begin(), table->end(), address,
        [](const BreakpointSpec& bp, uint64_t addr) {
            return bp.address < addr;
        });

    if (it == table->end() || it->address != address) return std::nullopt;
    return *it;
}

int GateManager::isBreakpoint(uint64_t address, gate_t& gate) {
    return findBreakpoint(address, gate).has_value() ? 1 : 0;
}

int GateManager::runBreakpointScript(const BreakpointSpec &breakpoint, unsigned vcpu, uint64_t pc) {
    if (breakpoint.script_path.empty()) {
        debug("[breakpoints] script breakpoint at 0x%llx has no script path\n",
              static_cast<unsigned long long>(breakpoint.address));
        return -1;
    }

    std::error_code ec;
    if (!std::filesystem::exists(breakpoint.script_path, ec)) {
        debug("[breakpoints] script path does not exist: %s\n",
              breakpoint.script_path.c_str());
    }

    char pc_arg_buf[32];
    char vcpu_arg_buf[16];
    std::snprintf(pc_arg_buf, sizeof(pc_arg_buf), "0x%llx", static_cast<unsigned long long>(pc));
    std::snprintf(vcpu_arg_buf, sizeof(vcpu_arg_buf), "%u", vcpu);

    std::string first_error;
    for (const auto &argv : python_command_candidates(breakpoint.script_path, pc_arg_buf, vcpu_arg_buf)) {
        debug("[breakpoints] launching script %s via %s pc=%s vcpu=%s\n",
              breakpoint.script_path.c_str(),
              argv[0].c_str(),
              pc_arg_buf,
              vcpu_arg_buf);
        ProcessResult result = run_process(argv);
        if (!result.started) {
            if (first_error.empty()) {
                first_error = argv[0] + ": " + std::strerror(result.error_code);
            }
            debug("[breakpoints] could not start %s: %s\n",
                  argv[0].c_str(),
                  std::strerror(result.error_code));
            continue;
        }

        debug("[breakpoints] script %s started via %s\n",
              breakpoint.script_path.c_str(),
              argv[0].c_str());
        return 0;
    }

    debug("[breakpoints] failed to start Python script %s%s%s\n",
          breakpoint.script_path.c_str(),
          first_error.empty() ? "" : ": ",
          first_error.c_str());
    return -1;
}

int GateManager::applyBreakpointPatch(const BreakpointSpec &breakpoint) {
    if (breakpoint.patch.bytes.empty()) {
        return 0;
    }

    GByteArray *buf = g_byte_array_sized_new(1);
    if (!buf) {
        debug("[breakpoints] failed to allocate patch byte buffer\n");
        return -1;
    }

    int failures = 0;
    for (const auto &[offset_or_address, byte] : breakpoint.patch.bytes) {
        const uint64_t write_address = breakpoint.patch.address != 0
            ? breakpoint.patch.address + offset_or_address
            : offset_or_address;

        g_byte_array_set_size(buf, 0);
        g_byte_array_append(buf, &byte, 1);
        if (!qemu_plugin_write_memory_vaddr(write_address, buf)) {
            failures++;
            debug("[breakpoints] patch write failed at 0x%llx\n",
                  static_cast<unsigned long long>(write_address));
        }
    }

    g_byte_array_free(buf, TRUE);
    return failures == 0 ? 0 : -1;
}


int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::function<int()> func) {
    (void)breakpoint;
    (void)gate;
    (void)func;
    return 0;
}

int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::string scriptPath) {
    (void)breakpoint;
    (void)gate;
    (void)scriptPath;
    return 0;
}
