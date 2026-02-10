#include "main.hpp"
#include "debug.hpp"
#include "memorydump.hpp"
#include "regdump.hpp"
#include "socket.hpp"
#include "gate.hpp"
#include "disasm.hpp"
#include "setreg.hpp"

#include <atomic>
#include <dlfcn.h>
#include <sstream>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <cstdlib>
#include <fstream>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
int vcpu_current_thread_index = 0;

char ScallopState::g_mem_path[256] = {0};
char ScallopState::g_reg_path[256] = {0};
FILE *ScallopState::g_out[MAX_VCPUS] = {nullptr};
FILE *ScallopState::binaryConfigs[MAX_VCPUS] = {nullptr};
int ScallopState::g_log_disas = 0;
timespec ScallopState::g_config_mtime[MAX_VCPUS] = {};
bool ScallopState::g_config_mtime_valid[MAX_VCPUS] = {false};
SymbolResolver ScallopState::g_resolver;

ScallopState scallopstate;

namespace
{
    std::atomic<bool> request_worker_running{false};
    std::thread request_worker;

    /**
     * Check requests every 1 millisecond. Run once!!!!!!
     */
    void start_request_worker()
    {
        bool expected = false;
        if (!request_worker_running.compare_exchange_strong(expected, true))
        {
            return;
        }
        request_worker = std::thread([]()
                                     {
        while (request_worker_running.load(std::memory_order_relaxed)) {
            scallopstate.update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } });
    }

    /**
     * Kill the thread handling requests.
     */
    void stop_request_worker()
    {
        bool expected = true;
        if (!request_worker_running.compare_exchange_strong(expected, false))
        {
            return;
        }
        if (request_worker.joinable())
        {
            request_worker.join();
        }
    }
} // namespace

namespace
{
    std::vector<FocusRange> read_focus_ranges_from_file();
    void write_focus_ranges_to_file(const std::vector<FocusRange> &ranges);

    std::filesystem::path resolve_config_dir(const std::string &binary_stem)
    {
        const char *home = std::getenv("HOME");
        if (home && *home)
        {
            std::filesystem::path dir = std::filesystem::path(home) / ".scallop" / binary_stem;
            std::error_code ec;
            std::filesystem::create_directories(dir, ec);
            if (!ec)
            {
                return dir;
            }
            debug("[config] failed to create %s: %s\n", dir.c_str(), ec.message().c_str());
        }
        return std::filesystem::temp_directory_path();
    }

    std::string basename_without_extension(const char *path)
    {
        if (!path || !*path)
        {
            return {};
        }
        return std::filesystem::path(path).stem().string();
    }

    void ensure_binary_context_ready_impl()
    {
        bool expected = false;
        if (!scallopstate.binary_ctx_ready.compare_exchange_strong(expected, true))
        {
            return;
        }

        const char *bin_path = qemu_plugin_path_to_binary();
        if (!bin_path || !*bin_path)
        {
            scallopstate.binary_ctx_ready.store(false);
            return;
        }

        scallopstate.binary_path = bin_path;
        scallopstate.binary_name = basename_without_extension(bin_path);
        if (scallopstate.binary_name.empty())
        {
            scallopstate.binary_ctx_ready.store(false);
        }
    }

    void ensure_binary_configs_ready_impl()
    {
        bool expected = false;
        if (!scallopstate.binary_configs_ready.compare_exchange_strong(expected, true))
        {
            return;
        }

        if (!scallopstate.binary_ctx_ready.load(std::memory_order_relaxed))
        {
            scallopstate.binary_configs_ready.store(false);
            return;
        }

        const std::filesystem::path base_dir = resolve_config_dir(scallopstate.binary_name);

        for (unsigned i = 0; i < MAX_VCPUS; i++)
        {
            std::string configFilename =
                "config" + scallopstate.binary_name + "_vcpu" + std::to_string(i) + ".txt";
            std::filesystem::path configPath = base_dir / configFilename;

            FILE *cfg = fopen(configPath.c_str(), "r+");
            if (!cfg)
            {
                cfg = fopen(configPath.c_str(), "w+");
            }

            if (!cfg)
            {
                fprintf(stderr, "[branchlog] failed to open '%s'\n", configPath.c_str());
                scallopstate.binaryConfigs[i] = stderr;
                continue;
            }

            setvbuf(cfg, NULL, _IOLBF, 0);
            scallopstate.binaryConfigs[i] = cfg;
            scallopstate.getGates().loadBreakpointsFromFile(i, cfg);
            struct stat st;
            if (fstat(fileno(cfg), &st) == 0) {
                scallopstate.g_config_mtime[i] = st.st_mtim;
                scallopstate.g_config_mtime_valid[i] = true;
            }
        }
        scallopstate.getGates().setFocusRanges(read_focus_ranges_from_file());
    }

    bool config_mtime_changed(unsigned vcpu)
    {
        if (vcpu >= MAX_VCPUS) {
            return false;
        }
        FILE *cfg = scallopstate.binaryConfigs[vcpu];
        if (!cfg || cfg == stderr) {
            return false;
        }
        int fd = fileno(cfg);
        if (fd < 0) {
            return false;
        }
        struct stat st;
        if (fstat(fd, &st) != 0) {
            return false;
        }
        if (!scallopstate.g_config_mtime_valid[vcpu]) {
            scallopstate.g_config_mtime[vcpu] = st.st_mtim;
            scallopstate.g_config_mtime_valid[vcpu] = true;
            return false;
        }
        const timespec &last = scallopstate.g_config_mtime[vcpu];
        if (st.st_mtim.tv_sec != last.tv_sec || st.st_mtim.tv_nsec != last.tv_nsec) {
            scallopstate.g_config_mtime[vcpu] = st.st_mtim;
            return true;
        }
        return false;
    }

    std::vector<FocusRange> read_focus_ranges_from_file()
    {
        std::vector<FocusRange> ranges;
        const std::filesystem::path path = scallop_focus_ranges_path();
        std::ifstream in(path);
        if (!in.is_open()) {
            return ranges;
        }

        const uint64_t base = scallop_runtime_base();
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("focus_ranges", 0) == 0) {
                continue;
            }
            std::istringstream iss(line);
            std::string a, b;
            if (!(iss >> a >> b)) {
                continue;
            }
            try {
                size_t idx1 = 0;
                size_t idx2 = 0;
                uint64_t lo = std::stoull(a, &idx1, 0);
                uint64_t hi = std::stoull(b, &idx2, 0);
                if (idx1 == 0 || idx2 == 0) {
                    continue;
                }
                ranges.push_back(FocusRange{base + lo, base + hi});
            } catch (...) {
                continue;
            }
        }
        return ranges;
    }

    void write_focus_ranges_to_file(const std::vector<FocusRange> &ranges)
    {
        const std::filesystem::path path = scallop_focus_ranges_path();
        FILE *f = fopen(path.c_str(), "w");
        if (!f) {
            debug("[focus] failed to open %s\n", path.c_str());
            return;
        }
        fprintf(f, "focus_ranges\n");
        const uint64_t base = scallop_runtime_base();
        for (const auto &r : ranges) {
            uint64_t lo = r.lo;
            uint64_t hi = r.hi;
            if (base != 0) {
                if (lo >= base) lo -= base;
                if (hi >= base) hi -= base;
            }
            fprintf(f, "0x%llx 0x%llx\n",
                    static_cast<unsigned long long>(lo),
                    static_cast<unsigned long long>(hi));
        }
        fflush(f);
        fclose(f);
    }

    /**
     * Normalizes all requests to be lowercase, no newlines or carriage returns,
     * keeps whitespace to max one character, and leaves non ASCII bytes untouched.
     */
    std::string normalize_request(const std::string &input)
    {
        std::string normalized;
        normalized.reserve(input.size());
        bool last_was_space = false;
        for (unsigned char c : input)
        {
            if (c == '\r' || c == '\n')
            {
                continue;
            }
            if (c == ' ' || c == '\t' || c == '\f')
            {
                if (!last_was_space && !normalized.empty())
                {
                    normalized.push_back(' ');
                }
                last_was_space = true;
            }
            else
            {

                if (c >= 'A' && c <= 'Z')
                {

                    // Convert uppercase to lowercase
                    // by adding 32
                    c += 32;
                }

                normalized.push_back(static_cast<char>((c)));
                last_was_space = false;
            }
        }
        if (!normalized.empty() && normalized.back() == ' ')
        {
            normalized.pop_back();
        }
        return normalized;
    }
} // namespace

std::filesystem::path scallop_config_dir()
{
    ensure_binary_context_ready();
    if (!scallopstate.binary_ctx_ready.load(std::memory_order_relaxed)) {
        return std::filesystem::temp_directory_path();
    }
    return resolve_config_dir(scallopstate.binary_name);
}

std::filesystem::path scallop_base_address_path()
{
    return scallop_config_dir() / "base_address.txt";
}

std::filesystem::path scallop_focus_ranges_path()
{
    return scallop_config_dir() / "focus_ranges.txt";
}

uint64_t scallop_runtime_base()
{
    uint64_t base = scallopstate.g_resolver.getCurrentRuntimeBase();
    if (base != 0) {
        return base;
    }

    ensure_binary_context_ready();
    if (!scallopstate.binary_path.empty()) {
        std::ifstream in("/proc/self/maps");
        if (in.is_open()) {
            std::string line;
            uint64_t best = 0;
            while (std::getline(in, line)) {
                unsigned long long start = 0;
                unsigned long long end = 0;
                char perms[5] = {0};
                char path_buf[512] = {0};
                int parsed = std::sscanf(line.c_str(), "%llx-%llx %4s %*s %*s %*s %511s",
                                         &start, &end, perms, path_buf);
                if (parsed < 4) {
                    continue;
                }
                std::string path = path_buf;
                if (path.find(scallopstate.binary_path) == std::string::npos) {
                    continue;
                }
                if (best == 0 || start < best) {
                    best = static_cast<uint64_t>(start);
                }
            }
            if (best != 0) {
                scallopstate.g_resolver.set_runtime_base(best);
                return best;
            }
        }
    }

    base = qemu_plugin_start_code();
    scallopstate.g_resolver.set_runtime_base(base);
    return base;
}

void ensure_binary_context_ready()
{
    ensure_binary_context_ready_impl();
}

void ensure_binary_configs_ready()
{
    ensure_binary_configs_ready_impl();
}

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    (void)vcpu_index;
    ensure_binary_context_ready();
    ensure_binary_configs_ready();
}

/**
 * All the scallop_request definitions
 */
scallop_request::scallop_request(std::string _request, SCALLOP_REQUEST_TYPE _importance)
{
    request = _request;
    importance = _importance;
}
std::string scallop_request::getRequest()
{
    return request;
}
SCALLOP_REQUEST_TYPE scallop_request::getImportance()
{
    return importance;
}

/*=========================*/

/**
 * It orders requests by importance: if you do one thing before the other, information may be wrong. For example,
 * if you step before you set memory or set a register, it won't set at the assumed time,
 * making the program update the instruction AFTER it was supposed to. If you get mem or
 * get reg before you step, you won't have the updated memory and changes won't be made correctly.
 */
scallop_request ScallopState::highestPriorityReq(bool allow_qemu_ops)
{
    std::lock_guard<std::mutex> lock(requests_mutex_);

    if (requests.empty())
    {
        return scallop_request("", SCALLOP_REQUEST_TYPE::defaultReq);
    }

    std::size_t highestReqIndex = 0;
    for (std::size_t i = 1; i < requests.size(); i++)
    {
        if (requests.at(highestReqIndex).getImportance() < requests.at(i).getImportance())
        {
            highestReqIndex = i;
        }
    }

    scallop_request highestRequest = requests.at(highestReqIndex);
    requests.erase(requests.begin() +
                   static_cast<std::vector<scallop_request>::difference_type>(highestReqIndex));
    return highestRequest;
}

/**
 * Identify the type of request that was sent over, and assign the proper enum for it.
 * This keeps code organized and prevents unnecessary string comparison boilerplate
 */
SCALLOP_REQUEST_TYPE ScallopState::classifyRequest(const std::string &request) const
{
    std::string normalized = normalize_request(request);

    auto starts_with = [&normalized](const char *prefix)
    {
        return normalized.rfind(prefix, 0) == 0;
    };

    debug("req = %s\n", normalized.c_str());

    if (starts_with("get memory") || starts_with("memdump"))
    {
        return SCALLOP_REQUEST_TYPE::getMem;
    }
    if (starts_with("set memory") || starts_with("memset"))
    {
        return SCALLOP_REQUEST_TYPE::setMem;
    }
    if (starts_with("get registers") || starts_with("get regs") || normalized == "regs")
    {
        return SCALLOP_REQUEST_TYPE::getReg;
    }
    if (starts_with("get vcpu") || normalized == "vcpu" || normalized == "vcpus")
    {
        return SCALLOP_REQUEST_TYPE::getVcpu;
    }
    if (starts_with("set registers") || starts_with("regs set"))
    {
        return SCALLOP_REQUEST_TYPE::setReg;
    }
    if (starts_with("step"))
    {
        return SCALLOP_REQUEST_TYPE::step;
    }
    if (starts_with("resume"))
    {
        return SCALLOP_REQUEST_TYPE::resume;
    }
    if (starts_with("break"))
    {
        return SCALLOP_REQUEST_TYPE::breakpoint;
    }
    if (starts_with("unbreak") || starts_with("delete break") || starts_with("del break"))
    {
        return SCALLOP_REQUEST_TYPE::deleteBreakpoint;
    }
    if (starts_with("defocus") || starts_with("unfocus"))
    {
        return SCALLOP_REQUEST_TYPE::defocusMem;
    }
    if (starts_with("focus") || normalized.find(';') != std::string::npos)
    {
        return SCALLOP_REQUEST_TYPE::focusMem;
    }
    return SCALLOP_REQUEST_TYPE::defaultReq;
}

/**
 *
 */
void ScallopState::enqueueRawRequest(const std::string &request)
{
    const auto importance = classifyRequest(request);
    std::lock_guard<std::mutex> lock(requests_mutex_);
    requests.emplace_back(request, importance);
}

/**
 * Attach the TCP socket to the ScallopState
 */
void ScallopState::attachSocket(std::unique_ptr<ScallopSocket> socket)
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    socket_ = std::move(socket);
}

/**
 * @return ScallopSocket socket
 */
ScallopSocket *ScallopState::socket()
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    return socket_.get();
}

const ScallopSocket *ScallopState::socket() const
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    return socket_.get();
}

GateManager &ScallopState::getGates()
{
    return gates;
}

qemu_plugin_id_t ScallopState::getID()
{
    return id;
}

void ScallopState::setID(qemu_plugin_id_t id)
{
    this->id = id;
}

/**
 * This runs through the queue of requests that the front end made. It does it in order of
 * importance: if you do one thing before the other, information may be wrong. For example,
 * if you step before you set memory or set a register, it won't set at the assumed time,
 * making the program update the instruction AFTER it was supposed to. If you get mem or
 * get reg before you step, you won't have the updated memory and changes won't be made correctly.
 */
int ScallopState::update(int vcpu)
{
    //debug("at head of update\n");
    scallop_request req("", SCALLOP_REQUEST_TYPE::defaultReq); // Default initialize
    while ((req = highestPriorityReq(false)).getImportance() != SCALLOP_REQUEST_TYPE::defaultReq)
    {
        switch (req.getImportance())
        {
        case SCALLOP_REQUEST_TYPE::getMem:
        {
            uint64_t addr;
            int n;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
    
            // Read the request arguments from the req
            if (sscanf(req.getRequest().c_str(), "get memory 0x%llx %d %d %d", &addr, &n, &vcpu_id, &thread_id) != 4 &&
                sscanf(req.getRequest().c_str(), "get memory 0x%llx %d %d %63s", &addr, &n, &vcpu_id, thread_name) != 4)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            
            scallop_mem_arguments* memArgs;

            // If setting the flags and arguments doesn't succeed, continue
            if (setFlagAndInitArguments<scallop_mem_arguments>(vcpu_id, VCPU_OP_DUMP_MEM, &memArgs)) {
                //debug("fail");
                break;
            }
            
            // Define args 
            memArgs->mem_addr = addr;
            memArgs->mem_size = n;

            // Set the flags arguments to memArgs
            setArguments(vcpu_id, VCPU_OP_DUMP_MEM, memArgs);
            
            break;

        }
        case SCALLOP_REQUEST_TYPE::getReg:
        {
            int* throwaway;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "get regs %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get regs %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "get registers %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get registers %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "regs %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "regs %d %63s", &vcpu_id, thread_name) != 2)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            setFlagAndInitArguments<int>(vcpu_id, VCPU_OP_DUMP_REGS, &throwaway);
            break;
        }
        case SCALLOP_REQUEST_TYPE::getVcpu:
        {
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "get vcpu %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get vcpu %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "get vcpus %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get vcpus %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpu %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpu %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpus %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpus %d %63s", &vcpu_id, thread_name) != 2)
            {
                break;
            }
            (void)vcpu_id;
            (void)thread_id;
            (void)thread_name;
            const int vcpus = qemu_plugin_num_vcpus();
            constexpr int threads_per_vcpu = 1;
            const int total_threads = vcpus * threads_per_vcpu;
            char response[128];
            snprintf(response, sizeof(response),
                     "vcpu_info vcpus=%d threads_per_vcpu=%d total_threads=%d\n",
                     vcpus, threads_per_vcpu, total_threads);
            debug("%s\n", response);
            if (auto *sock = scallopstate.socket())
            {
                sock->sendLine(response);
            }
            break;
        }
        case SCALLOP_REQUEST_TYPE::setMem:
        {
            uint64_t addr;
            int n;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
    
            // Read the request arguments from the req
            if (sscanf(req.getRequest().c_str(), "set memory 0x%llx %d %d %d", &addr, &n, &vcpu_id, &thread_id) != 4 &&
                sscanf(req.getRequest().c_str(), "set memory 0x%llx %d %d %63s", &addr, &n, &vcpu_id, thread_name) != 4)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            
            scallop_mem_arguments* memArgs;

            // If setting the flags and arguments doesn't succeed, continue
            if (setFlagAndInitArguments<scallop_mem_arguments>(vcpu_id, VCPU_OP_SET_MEM, &memArgs)) {
                //debug("fail");
                break;
            }
            
            // Define args 
            memArgs->mem_addr = addr;
            memArgs->mem_size = n;


            // Set the flags arguments to memArgs
            setArguments(vcpu_id, VCPU_OP_SET_MEM, memArgs);
            
            break;
        }
        case SCALLOP_REQUEST_TYPE::setReg:
        {
            //vcpu_op[vcpu].flags |= vcpu_operation_t::VCPU_OP_SET_REGS;
            break;
        }
        case SCALLOP_REQUEST_TYPE::step:
        {
            int steps;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "step %d %d %d", &steps, &vcpu_id, &thread_id) != 3 &&
                sscanf(req.getRequest().c_str(), "step %d %d %63s", &steps, &vcpu_id, thread_name) != 3)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            ensure_binary_context_ready();
            ensure_binary_configs_ready();
            if (vcpu_id >= 0 && vcpu_id < static_cast<int>(MAX_VCPUS)) {
                if (config_mtime_changed(static_cast<unsigned>(vcpu_id))) {
                    scallopstate.getGates().loadBreakpointsFromFile(
                        static_cast<unsigned>(vcpu_id),
                        scallopstate.binaryConfigs[static_cast<unsigned>(vcpu_id)]);
                }
            }
            scallopstate.getGates().stepIfNeeded(vcpu_id, steps);
            break;
        }
        case SCALLOP_REQUEST_TYPE::resume:
        {
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "resume %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "resume %d %63s", &vcpu_id, thread_name) != 2)
            {
                break;
            }
            (void)vcpu_id;
            (void)thread_id;
            (void)thread_name;
            scallopstate.getGates().resumeAll();
            break;
        }
        case SCALLOP_REQUEST_TYPE::breakpoint:
        {
            uint64_t addr;
            int vcpu_id;
            int thread_id;
            char thread_name[64];

            // Read the request arguments from the req
            if (sscanf(req.getRequest().c_str(), "break 0x%llx %d %d", &addr, &vcpu_id, &thread_id) != 3 &&
                sscanf(req.getRequest().c_str(), "break 0x%llx %d %63s", &addr, &vcpu_id, thread_name) != 3)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;

            const uint64_t base = scallop_runtime_base();
            const uint64_t runtime_addr = base + addr;
            debug("%s ...... parsed val = %llx (base=%llx runtime=%llx)",
                  req.getRequest().c_str(),
                  static_cast<unsigned long long>(addr),
                  static_cast<unsigned long long>(base),
                  static_cast<unsigned long long>(runtime_addr));
            scallopstate.getGates().addBreakpoint(runtime_addr, vcpu_id);
            break;
        }
        case SCALLOP_REQUEST_TYPE::deleteBreakpoint:
        {
            uint64_t addr = 0;
            int vcpu_id = -1;
            bool has_vcpu = false;

            const std::string normalized = normalize_request(req.getRequest());
            std::istringstream iss(normalized);
            std::vector<std::string> parts;
            for (std::string tok; iss >> tok; )
            {
                parts.push_back(std::move(tok));
            }

            int addr_index = -1;
            if (!parts.empty() && parts[0] == "unbreak")
            {
                addr_index = 1;
            }
            else if (parts.size() >= 2 && parts[0] == "delete" && parts[1] == "break")
            {
                addr_index = 2;
            }
            else if (parts.size() >= 2 && parts[0] == "del" && parts[1] == "break")
            {
                addr_index = 2;
            }

            if (addr_index < 0 || addr_index >= static_cast<int>(parts.size()))
            {
                debug("[breakpoints] delete parse failed: %s\n", req.getRequest().c_str());
                break;
            }

            char *end = nullptr;
            addr = std::strtoull(parts[addr_index].c_str(), &end, 0);
            if (!end || *end != '\0')
            {
                debug("[breakpoints] delete invalid addr: %s\n", parts[addr_index].c_str());
                break;
            }

            const int vcpu_index = addr_index + 1;
            if (vcpu_index < static_cast<int>(parts.size()))
            {
                vcpu_id = std::atoi(parts[vcpu_index].c_str());
                has_vcpu = true;
            }

            const uint64_t base = scallop_runtime_base();
            const uint64_t runtime_addr = base + addr;
            debug("[breakpoints] delete req='%s' addr=%llx base=%llx runtime=%llx has_vcpu=%d vcpu=%d\n",
                  req.getRequest().c_str(),
                  static_cast<unsigned long long>(addr),
                  static_cast<unsigned long long>(base),
                  static_cast<unsigned long long>(runtime_addr),
                  has_vcpu ? 1 : 0, vcpu_id);
            if (has_vcpu)
            {
                scallopstate.getGates().deleteBreakpoint(runtime_addr, vcpu_id);
            }
            else
            {
                for (unsigned i = 0; i < MAX_VCPUS; i++)
                {
                    scallopstate.getGates().deleteBreakpoint(runtime_addr, static_cast<int>(i));
                }
            }
            break;
        }
        case SCALLOP_REQUEST_TYPE::focusMem:
        {
            unsigned long long low = 0;
            unsigned long long high = 0;
            int vcpu_id = 0;
            int thread_id = 0;
            char thread_name[64];
            std::string normalized = normalize_request(req.getRequest());
            const char *s = normalized.c_str();
            if (normalized.rfind("focus ", 0) == 0) {
                s += 6;
            }
            if (sscanf(s, "%llu;%llu %d %d", &low, &high, &vcpu_id, &thread_id) != 4 &&
                sscanf(s, "%llu;%llu %d %63s", &low, &high, &vcpu_id, thread_name) != 4)
            {
                break;
            }
            (void)vcpu_id;
            (void)thread_id;
            (void)thread_name;
            if (low == 0 && high == 0) {
                scallopstate.getGates().clearFocusRanges();
            } else {
                scallopstate.getGates().addFocusRange(static_cast<uint64_t>(low), static_cast<uint64_t>(high));
            }
            write_focus_ranges_to_file(scallopstate.getGates().getFocusRanges());
            break;
        }
        case SCALLOP_REQUEST_TYPE::defocusMem:
        {
            unsigned long long low = 0;
            unsigned long long high = 0;
            int vcpu_id = 0;
            int thread_id = 0;
            char thread_name[64];
            std::string normalized = normalize_request(req.getRequest());
            const char *s = normalized.c_str();
            if (normalized.rfind("defocus ", 0) == 0) {
                s += 8;
            } else if (normalized.rfind("unfocus ", 0) == 0) {
                s += 8;
            }
            if (sscanf(s, "%llu;%llu %d %d", &low, &high, &vcpu_id, &thread_id) != 4 &&
                sscanf(s, "%llu;%llu %d %63s", &low, &high, &vcpu_id, thread_name) != 4)
            {
                break;
            }
            (void)vcpu_id;
            (void)thread_id;
            (void)thread_name;
            if (low == 0 && high == 0) {
                scallopstate.getGates().clearFocusRanges();
            } else {
                scallopstate.getGates().removeFocusRange(static_cast<uint64_t>(low), static_cast<uint64_t>(high));
            }
            write_focus_ranges_to_file(scallopstate.getGates().getFocusRanges());
            break;
        }
        }
    }

    return 0;
}



int ScallopState::setArguments(int vcpu, vcpu_operation_t cmd, void* args) {
    vcpu_op[vcpu].arguments[std::countr_zero(static_cast<uint64_t>(cmd))] = args; 
    return 0;
}


int ScallopState::removeFlag(int vcpu, vcpu_operation_t cmd) {
    // FLAGS AND (FLAGS AND NOT CMD) = turning off only the inputted flag
    scallopstate.vcpu_op[vcpu].flags.store(scallopstate.vcpu_op[vcpu].flags.load(std::memory_order_relaxed) & (~cmd), std::memory_order_relaxed);
    return 0;
}

bool ScallopState::getIsFlagQueued(int vcpu, vcpu_operation_t cmd) {
    return (scallopstate.vcpu_op[vcpu].flags.load(std::memory_order_relaxed) & cmd) != cmd;
}

/**
 * Handle when the plugin is told to die.
 */
static void plugin_exit(qemu_plugin_id_t id, void *u)
{
    scallopstate.getGates().pauseAll();
    stop_request_worker();
    for (unsigned i = 0; i < MAX_VCPUS; i++) {
        if (scallopstate.g_out[i] && scallopstate.g_out[i] != stderr) {
            fflush(scallopstate.g_out[i]);
            fclose(scallopstate.g_out[i]);
            scallopstate.g_out[i] = nullptr;
        }
        if (scallopstate.binaryConfigs[i] && scallopstate.binaryConfigs[i] != stderr) {
            fflush(scallopstate.binaryConfigs[i]);
            fclose(scallopstate.binaryConfigs[i]);
            scallopstate.binaryConfigs[i] = nullptr;
        }
    }
}

/**
 * On initialization
 */
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{

    (void)info;
    const char *outfile = NULL;

    scallopstate.setID(id);

    initDebug();
    debug("[install] pid=%ld\n", (long)getpid());

    for (int i = 0; i < argc; i++)
    {
        if (!strncmp(argv[i], "file=", 5))
            outfile = argv[i] + 5;
        else if (!strncmp(argv[i], "out=", 4))
            outfile = argv[i] + 4;
        else if (!strcmp(argv[i], "disas=1"))
            scallopstate.g_log_disas = 1;
        else if (!strncmp(argv[i], "memfile=", 8))
            snprintf(scallopstate.g_mem_path, sizeof(scallopstate.g_mem_path), "%s", argv[i] + 8);
        else if (!strncmp(argv[i], "regfile=", 8))
            snprintf(scallopstate.g_reg_path, sizeof(scallopstate.g_reg_path), "%s", argv[i] + 8);
    }
    if (!*scallopstate.g_mem_path) {
        std::filesystem::path path = std::filesystem::temp_directory_path() / "memdump.txt";
        snprintf(scallopstate.g_mem_path, sizeof(scallopstate.g_mem_path), path.c_str());
    }
    if (!*scallopstate.g_reg_path) {
        std::filesystem::path path = std::filesystem::temp_directory_path() / "regdump.txt";
        snprintf(scallopstate.g_reg_path, sizeof(scallopstate.g_reg_path), path.c_str());
    }

    // Open per-vcpu branch log files
    for (unsigned i = 0; i < MAX_VCPUS; i++) {
        // Open all the branchlogs containing instruction data
        std::string outFilename = "branchlog" + std::to_string(i) + ".csv";
        scallopstate.g_out[i] = fopen((std::filesystem::temp_directory_path() / outFilename).c_str(), "w+");
        if (!scallopstate.g_out[i]) {
            fprintf(stderr, "[branchlog] failed to open '%s'\n", outFilename.c_str());
            scallopstate.g_out[i] = stderr;
        }
        setvbuf(scallopstate.g_out[i], NULL, _IOLBF, 0);

    }

    // Probably shouldnt hardcode this but whatever
    scallopstate.g_log_disas = 1;

    // Debug
    fprintf(stderr, "[branchlog] plugin install OK (file=%s mem=%s reg=%s)\n",
            outfile ? outfile : "(stderr)", scallopstate.g_mem_path, scallopstate.g_reg_path);
    fflush(stderr);

    // Write CSV headers to all vcpu files
    for (unsigned i = 0; i < MAX_VCPUS; i++) {
        fprintf(scallopstate.g_out[i], "pc,kind,branch_target,fallthrough,tb_vaddr,bytes%s,symbol\n", scallopstate.g_log_disas ? ",disas" : "");
        fflush(scallopstate.g_out[i]);
    }

    Dl_info soinfo{};
    if (dladdr((void *)&qemu_plugin_install, &soinfo) && soinfo.dli_fname)
    {
        fprintf(stderr, "[branchlog] using plugin %s\n", soinfo.dli_fname);
        fflush(stderr);
    }

    scallopstate.getGates().initAll();

    auto control_socket = std::make_unique<ScallopSocket>(scallopstate);
    if (!control_socket->start())
    {
        debug("CONTROL SOCKET FAILED!!!! ");
        fprintf(stderr, "[branchlog] WARNING: control socket failed\n");
    }
    else
    {
        debug("Server success! listening on port %u\n",
              static_cast<unsigned>(control_socket->port()));
        fprintf(stderr, "[branchlog] control socket listening on port %u\n",
                static_cast<unsigned>(control_socket->port()));
        scallopstate.attachSocket(std::move(control_socket));
        start_request_worker();
    }

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
