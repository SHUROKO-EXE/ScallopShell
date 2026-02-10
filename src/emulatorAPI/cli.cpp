#include "emulatorAPI.hpp"

std::atomic_uint64_t Emulator::flags[MAX_VCPUS];

int Emulator::setFlag(int vcpu, vcpu_operation_t cmd) {
    // Set the flag to be the cmd
    flags[vcpu].store(flags[vcpu].load(std::memory_order_relaxed) | cmd, std::memory_order_relaxed); 

    // Get how many shifts the flag was at ( 0b01000 would = 3 )
    uint64_t flagIndex = std::countr_zero(static_cast<uint64_t>(cmd));

    return 0;
}

int Emulator::removeFlag(int vcpu, vcpu_operation_t cmd) {
    // FLAGS AND (FLAGS AND NOT CMD) = turning off only the inputted flag
    flags[vcpu].store(flags[vcpu].load(std::memory_order_relaxed) & (~cmd), std::memory_order_relaxed);
    return 0;
}

bool Emulator::getIsFlagQueued(int vcpu, vcpu_operation_t cmd) {
    return (flags[vcpu].load(std::memory_order_relaxed) & cmd) == cmd;
}

int Emulator::addBreakpoint(uint64_t address, std::string &comment)
{
    const uint64_t base = getRuntimeBaseAddress();
    if (base == 0) {
        std::cerr << "[cli] runtime base not available; skipping breakpoint\n";
        return 1;
    }
    const uint64_t offset = address - base;

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "break 0x%llx %d %s\n",
                  offset, selectedVCPU, selectedThread.c_str());

    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    return 0;
}

int Emulator::deleteBreakpoint(uint64_t address)
{
    const uint64_t base = getRuntimeBaseAddress();
    if (base == 0) {
        std::cerr << "[cli] runtime base not available; skipping unbreak\n";
        return 1;
    }
    const uint64_t offset = address - base;

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "unbreak 0x%llx %d %s\n",
                  offset, selectedVCPU, selectedThread.c_str());
    std::cerr << "[cli] send delete breakpoint: " << cmd;

    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    return 0;
}

static std::filesystem::path configPathForVCPU(const std::string &binaryStem, int vcpuIndex)
{
    if (binaryStem.empty() || vcpuIndex < 0) {
        return {};
    }

    std::string filename = "config" + binaryStem + "_vcpu" + std::to_string(vcpuIndex) + ".txt";

    const char *home = std::getenv("HOME");
    if (home && *home) {
        std::filesystem::path homePath = std::filesystem::path(home) / ".scallop" / binaryStem / filename;
        if (std::filesystem::exists(homePath)) {
            return homePath;
        }
    }

    std::filesystem::path tempPath = std::filesystem::temp_directory_path() / filename;
    if (std::filesystem::exists(tempPath)) {
        return tempPath;
    }

    return {};
}

static std::filesystem::path basePathForBinary(const std::string &binaryStem)
{
    if (binaryStem.empty()) {
        return {};
    }

    const std::string filename = "base_address.txt";
    const char *home = std::getenv("HOME");
    if (home && *home) {
        std::filesystem::path homePath = std::filesystem::path(home) / ".scallop" / binaryStem / filename;
        if (std::filesystem::exists(homePath)) {
            return homePath;
        }
    }

    std::filesystem::path tempPath = std::filesystem::temp_directory_path() / filename;
    if (std::filesystem::exists(tempPath)) {
        return tempPath;
    }

    return {};
}

static std::optional<uint64_t> readBaseAddressFromFile(const std::filesystem::path &path)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        return std::nullopt;
    }

    std::string token;
    if (!(in >> token)) {
        return std::nullopt;
    }

    try {
        size_t idx = 0;
        uint64_t addr = std::stoull(token, &idx, 0);
        if (idx > 0) {
            return addr;
        }
    } catch (...) {
        return std::nullopt;
    }

    return std::nullopt;
}

static std::string trimLine(const std::string &s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) {
        return {};
    }
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<uint64_t> Emulator::getBreakpointsFromConfig(int vcpuIndex)
{
    if (vcpuIndex < 0) {
        vcpuIndex = getSelectedVCPU();
    }

    std::vector<uint64_t> out;
    const uint64_t base = getRuntimeBaseAddress();
    if (base == 0) {
        return out;
    }
    const std::filesystem::path cfgPath = configPathForVCPU(binaryStem, vcpuIndex);
    if (cfgPath.empty()) {
        return out;
    }

    std::ifstream in(cfgPath);
    if (!in.is_open()) {
        return out;
    }

    std::string line;
    bool first_line = true;
    while (std::getline(in, line)) {
        if (first_line) {
            first_line = false;
            if (line.rfind("breakpoint_addr", 0) == 0) {
                continue;
            }
        }

        std::string t = trimLine(line);
        if (t.empty()) {
            continue;
        }

        try {
            size_t idx = 0;
            uint64_t addr = std::stoull(t, &idx, 0);
            if (idx > 0) {
                out.push_back(base + addr);
            }
        } catch (...) {
            continue;
        }
    }

    return out;
}

std::filesystem::path Emulator::getBreakpointConfigPath(int vcpuIndex)
{
    if (vcpuIndex < 0) {
        vcpuIndex = getSelectedVCPU();
    }
    return configPathForVCPU(binaryStem, vcpuIndex);
}

uint64_t Emulator::getRuntimeBaseAddress()
{
    static std::filesystem::path last_path;
    static std::filesystem::file_time_type last_mtime{};
    static bool last_mtime_valid = false;
    static std::atomic_uint64_t cached_base{0};

    const std::filesystem::path path = basePathForBinary(binaryStem);
    if (path.empty()) {
        return cached_base.load(std::memory_order_relaxed);
    }

    std::error_code ec;
    auto mtime = std::filesystem::last_write_time(path, ec);
    if (!ec) {
        if (!last_mtime_valid || path != last_path || mtime != last_mtime) {
            last_path = path;
            last_mtime = mtime;
            last_mtime_valid = true;
            if (auto val = readBaseAddressFromFile(path)) {
                cached_base.store(*val, std::memory_order_relaxed);
            }
        }
    }

    return cached_base.load(std::memory_order_relaxed);
}
