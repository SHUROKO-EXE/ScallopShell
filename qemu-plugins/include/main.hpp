#pragma once
#include <algorithm>
#include <atomic>

#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>
extern "C" {
    #include "qemu/qemu-plugin.h"
}
#include "gate.hpp"
#include "string"
#include "vector"
#include <memory>
#include <mutex>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include "functional"
#include <memory> 
#include "filesystem"

#include "symbols.hpp"

extern uint64_t cur_pc;

/**
 * This is the request type. We can handle requests in order of importance.
 */
enum class SCALLOP_REQUEST_TYPE {
    defaultReq,
    getMem,
    getReg,
    getVcpu,
    step,
    resume,
    setMem,
    setReg,
    breakpoint,
    deleteBreakpoint,
    focusMem,
    defocusMem
};

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


/**
 * This is where pending executions from requests are stored.
 * There's 64 arguments for each bit in the flag. 64 possible
 * commands at the moment.
 */
struct vcpu_pending_ops {
    std::atomic_uint64_t flags;
    std::atomic<void*> arguments[64];

    vcpu_pending_ops() : flags(0) {
        for (int i = 0; i < 64; i++) {
            arguments[i].store(nullptr, std::memory_order_relaxed);
        }
    }
};

struct scallop_mem_arguments{

    static constexpr int byteLength = 8;
    static constexpr int numberOfRows = 512;
    uint64_t mem_addr;
    int mem_size;
    uint8_t mem_data[byteLength*numberOfRows];

} ;

/**
 * Requests
 */
class scallop_request {

    std::string request; // The request saved by 
    SCALLOP_REQUEST_TYPE importance = SCALLOP_REQUEST_TYPE::defaultReq;

public:

    scallop_request(std::string _request, SCALLOP_REQUEST_TYPE _importance);

    std::string getRequest();
    SCALLOP_REQUEST_TYPE getImportance();
    

};

class ScallopSocket;

class ScallopState {
private:

    scallop_request highestPriorityReq(bool allow_qemu_ops);
    SCALLOP_REQUEST_TYPE classifyRequest(const std::string &request) const;

    mutable std::mutex requests_mutex_;
    std::unique_ptr<ScallopSocket> socket_;
    static inline qemu_plugin_id_t id = 0;
    GateManager gates; 
    
public:
    
    static SymbolResolver g_resolver;    

    // File paths for output
    static char g_mem_path[256];
    static char g_reg_path[256];
    static FILE *g_out[MAX_VCPUS];
    static FILE *binaryConfigs[MAX_VCPUS];
    static int g_log_disas;
    static timespec g_config_mtime[MAX_VCPUS];
    static bool g_config_mtime_valid[MAX_VCPUS];

    std::string binary_path;
    std::string binary_name;
    std::atomic<bool> binary_ctx_ready{false};
    std::atomic<bool> binary_configs_ready{false};

    vcpu_pending_ops vcpu_op[MAX_VCPUS];

    std::vector<scallop_request> requests;

    void attachSocket(std::unique_ptr<ScallopSocket> socket);
    ScallopSocket *socket();
    const ScallopSocket *socket() const;

    void enqueueRawRequest(const std::string &request);

    int update(int vcpu = 0);

    template<typename T>
    int setFlagAndInitArguments(int vcpu, vcpu_operation_t cmd, T** args) {
        // Set the flag to be the cmd
        vcpu_op[vcpu].flags.store(vcpu_op[vcpu].flags.load(std::memory_order_relaxed) | cmd, std::memory_order_relaxed); 

        // Get how many shifts the flag was at ( 0b01000 would = 3 )
        uint64_t flagIndex = std::countr_zero(static_cast<uint64_t>(cmd));

        if (args == nullptr) {
            return 0;
        }

        // Get the previous arguments to check if they are initialized
        T* newArgs = (T*)vcpu_op[vcpu].arguments[flagIndex].load(std::memory_order_relaxed);        

        // If memArgs hasn't been initialized yet
        if (newArgs == nullptr) {
            newArgs = new T;

            if (newArgs == nullptr) {
                return -1; // Failed allocation, so leave
            }
        
        }

        *args = newArgs;

        return 0;
    }

    int setArguments(int vcpu, vcpu_operation_t cmd, void* args);

    template<typename T>
    int getArguments(int vcpu, vcpu_operation_t cmd, T** args) {
        
        T* retArgs = (T*)vcpu_op[vcpu]
            .arguments[std::countr_zero(static_cast<uint64_t>(cmd))].load(std::memory_order_relaxed);

        if (retArgs == nullptr) {
            return -1;
        }

        *args = retArgs;
        return 0;
        
    }

    int removeFlag(int vcpu, vcpu_operation_t cmd);

    bool getIsFlagQueued(int vcpu, vcpu_operation_t cmd);

    GateManager& getGates();

    qemu_plugin_id_t getID();

    void setID(qemu_plugin_id_t id);

};

extern ScallopState scallopstate;
void ensure_binary_context_ready();
void ensure_binary_configs_ready();
std::filesystem::path scallop_config_dir();
std::filesystem::path scallop_base_address_path();
std::filesystem::path scallop_focus_ranges_path();
uint64_t scallop_runtime_base();

/**
 * For context: the purpose of this variable is to make sure that all 
 * threads have their own cpu index passed through to the functions they 
 * call. This is due to the restriction of arguments in functions further
 * down the call stack than the QEMU plugin callback. 
 */
extern int vcpu_current_thread_index; 
