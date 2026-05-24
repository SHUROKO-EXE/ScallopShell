#include "emulatorAPI.hpp"
#include "guihelpers.hpp"

struct PendingSetMem {
    uint64_t address = 0;
    int size = 0;
    std::vector<uint8_t> data;
};

std::optional<PendingSetMem> g_pending_setmem;
std::mutex g_pending_setmem_mu;





struct MemoryCache
{
    bool tryUpdateAgain = false;
    int modificationsMade = 0;
    int targetModifications = 0;
    uint64_t address = std::numeric_limits<uint64_t>::max();
    int span = -1;
    std::vector<uint8_t> data;
};

static std::unordered_map<std::string, MemoryCache> &memoryCaches()
{
    static std::unordered_map<std::string, MemoryCache> caches;
    return caches;
}
 
bool writeWholeFile(const std::string &path, const std::string &contents)
{
    
    static std::filesystem::path tempDir = std::filesystem::temp_directory_path();
    tempDir = tempDir / path;
    
    std::ofstream ofs(tempDir, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs)
        return false;
    ofs.write(contents.data(), (std::streamsize)contents.size());
    return ofs.good();
}

bool writeWholeFile(const std::string &path, const uint8_t *data, int n)
{

    if (!data || n <= 0)
        return false;

    static std::filesystem::path tempDir = std::filesystem::temp_directory_path();

    tempDir = tempDir / path;

    std::ofstream ofs(tempDir, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs)
        return false;

    ofs.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(n));
    return ofs.good();
}


std::vector<uint8_t>* Emulator::getMemory(uint64_t address, int n,
                                          int targetMods, const std::string &cacheKey)
{

    auto &cache = memoryCaches()[cacheKey];
    const uint64_t kNoAddress = std::numeric_limits<uint64_t>::max();

    // If addr = -1 was passed in, save it to the cache
    if (address != kNoAddress)
        cache.address = address;

    // If size changed, store it in cache.span
    if (n != -1)
        cache.span = n;

    // If the cache address = -1 or the size is less than 1
    if (cache.address == kNoAddress || cache.span <= 0)
    {
        return &cache.data; // Ret the data (probably nullptr)
    }
    
    const bool update_requested = getIsFlagQueued(0, VCPU_OP_DUMP_MEM);
    // If the flag isn't here and it isn't supposed to update again:
    if (!update_requested && !cache.tryUpdateAgain)
    {
        return &cache.data; // Return the old data
    }

    // Return how many times getMemory has to change 
    if (targetMods != -1)
    {
        cache.targetModifications = targetMods;
    }

    if (!update_requested)
    {
        return &cache.data;
    }

    // Decremement span because it's going to do another modification
    uint64_t span = static_cast<uint64_t>(cache.span - 1);
    uint64_t hi = cache.address;

    if (span > std::numeric_limits<uint64_t>::max() - cache.address)
        hi = std::numeric_limits<uint64_t>::max();
    else
        hi = cache.address + span;

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "get memory 0x%llx %d %d %s\n",
                  (unsigned long long)cache.address, n,
                  selectedVCPU, selectedThread.c_str());

    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    static std::filesystem::path tempFilePath = std::filesystem::temp_directory_path();
    std::ifstream memoryFile( tempFilePath / ("memdump" + std::to_string(getSelectedVCPU()) + ".txt"), std::ios::in);
    if (!memoryFile.is_open())
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    std::vector<std::string> bytes;
    std::string memoryDumpLine;
    while (std::getline(memoryFile, memoryDumpLine))
    {
        std::stringstream check1(memoryDumpLine);
        std::string intermediate;
        while (std::getline(check1, intermediate, ' '))
        {
            if (!intermediate.empty())
                bytes.push_back(intermediate);
        }
    }

    if (bytes.empty())
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    cache.data.clear();
    cache.data.reserve(bytes.size());
    for (const auto &byte : bytes)
    {
        uint8_t byteInt = 0;
        if (sscanf(byte.c_str(), "%hhx", &byteInt) == 1)
            cache.data.emplace_back(byteInt);
    }

    if (cache.data.empty())
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    if (cache.data.size() > static_cast<size_t>(cache.span))
        cache.data.resize(static_cast<size_t>(cache.span));

    const bool should_clear_flag = update_requested;
    if (cache.targetModifications > 0)
    {
        cache.modificationsMade++;
        if (cache.modificationsMade >= cache.targetModifications)
        {
            cache.targetModifications = 0;
            cache.modificationsMade = 0;
            cache.tryUpdateAgain = false;
            if (should_clear_flag)
            {
                removeFlag(0, VCPU_OP_DUMP_MEM);
            }
        }
        else
        {
            cache.tryUpdateAgain = true;
        }
    }
    else
    {
        cache.modificationsMade = 0;
        cache.tryUpdateAgain = false;
        if (should_clear_flag)
        {
            removeFlag(0, VCPU_OP_DUMP_MEM);
        }
    }

    return &cache.data;
}


int Emulator::modifyMemory(uint64_t address, std::vector<uint8_t>* data, int n) {
   
    if (getIsFlagQueued(0, VCPU_OP_SET_MEM) == false) 
        return 1;
    
    if (data == nullptr) {
        return 1;
    }

    // If data is empty OR bytes is <= 0 then ret
    if (data->empty() || n <= 0)
        return 1;

    const int copy_len = std::min(n, static_cast<int>(data->size()));
    std::string ret;
    std::string memoryDumpWrite; // String to save to file
    memoryDumpWrite.reserve(static_cast<size_t>(copy_len) * 3);

    // For each byte
    for (int i = 0; i < copy_len; ++i)
    {
        // Add to the memdump file
        memoryDumpWrite += hex1ByteStr(data->at(i));

        // If it's the 8th byte, newline
        if (((i + 1) % 8) == 0)
            memoryDumpWrite.push_back('\n');
        else
            memoryDumpWrite.push_back(' ');
    }

    // If it runs out early, add a newline at the end
    if (!memoryDumpWrite.empty() && memoryDumpWrite.back() != '\n')
        memoryDumpWrite.back() = '\n';

    // If writing the whole file works
    if (!writeWholeFile("memdump.txt", memoryDumpWrite))
        return 1;

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx %d %d %s\n",
                  (unsigned long long)address, copy_len,
                  selectedVCPU, selectedThread.c_str());
    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    
    removeFlag(0, VCPU_OP_SET_MEM);
    return 0;

}

int Emulator::modifyMemory(uint64_t address, uint8_t *data, int n)
{
    return 0;
    /*
    if (getIsFlagQueued(0, VCPU_OP_SET_MEM) == false) 
        return 0;
    
    // If data = nullptr OR bytes is <= 0 then ret
    if (!data || n <= 0)
        return 0;
    
    std::string ret;
    std::string memoryDumpWrite; // String to save to file
    memoryDumpWrite.reserve(static_cast<size_t>(n) * 3);

    // For each byte
    for (int i = 0; i < n; ++i)
    {
        // Add to the memdump file
        memoryDumpWrite += hex1ByteStr(data[i]);

        // If it's the 8th byte, newline
        if (((i + 1) % 8) == 0)
            memoryDumpWrite.push_back('\n');
        else
            memoryDumpWrite.push_back(' ');
    }

    // If it runs out early, add a newline at the end
    if (!memoryDumpWrite.empty() && memoryDumpWrite.back() != '\n')
        memoryDumpWrite.back() = '\n';

    // If writing the whole file works
    if (!writeWholeFile(kMemDump, memoryDumpWrite))
        return 0;

    uint64_t span = static_cast<uint64_t>(n - 1);
    uint64_t hi = address;
    if (span > std::numeric_limits<uint64_t>::max() - address)
        hi = std::numeric_limits<uint64_t>::max();
    else
        hi = address + span;

    // Send the command
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx;0x%llx\n",
                  (unsigned long long)address, (unsigned long long)hi);
    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return false;

    return ret.rfind("ok", 0) == 0; */
}


void Emulator::stageMemoryWrite(uint64_t address, const std::vector<uint8_t>& data, int n)
{
    if (n <= 0 || data.empty())
    {
        return;
    }
    PendingSetMem staged;
    staged.address = address;
    staged.size = std::min(n, static_cast<int>(data.size()));
    staged.data.assign(data.begin(), data.begin() + staged.size);

    std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
    g_pending_setmem = std::move(staged);
}

bool Emulator::hasStagedMemoryWrite()
{
    std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
    return g_pending_setmem.has_value();
}

int Emulator::flushStagedMemoryWrite()
{
    PendingSetMem staged;
    {
        std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
        if (!g_pending_setmem)
        {
            return 0;
        }
        staged = *g_pending_setmem;
        g_pending_setmem.reset();
    }

    int rc = modifyMemory(staged.address, &staged.data, staged.size);
    if (rc != 0)
    {
        std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
        g_pending_setmem = std::move(staged);
    }
    return rc;
}


