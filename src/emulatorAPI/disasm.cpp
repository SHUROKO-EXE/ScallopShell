#include "emulatorAPI.hpp"
#include <unordered_map>

static std::vector<InstructionInfo> instructionInfo;

// Per-VCPU index state
struct VCPUIndexState {
    std::vector<std::streamoff> lineOffsets;
    std::streamoff lastIndexedOffset = 0;
    uintmax_t lastIndexedSize = 0;
    bool headerSkipped = false;
    int cachedStart = -1;
    int cachedN = -1;
    uintmax_t cachedSize = 0;
};

static std::unordered_map<int, VCPUIndexState> vcpuIndexStates;


static std::string trim(std::string s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos)
        return std::string{};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static uint64_t parse_hex(const std::string &s)
{
    std::string t = trim(s);
    if (t.empty() || t == "0" || t == "0x0")
        return 0ULL;
    const char *p = t.c_str();
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
        p += 2;
    char *end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    return static_cast<uint64_t>(v);
}

static std::vector<std::string> parse_csv(const std::string &line)
{
    std::vector<std::string> out;
    std::string field;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i)
    {
        char c = line[i];
        if (in_quotes)
        {
            if (c == '"')
            {
                if (i + 1 < line.size() && line[i + 1] == '"')
                {
                    field.push_back('"');
                    ++i;
                }
                else
                {
                    in_quotes = false;
                }
            }
            else
                field.push_back(c);
        }
        else
        {
            if (c == '"')
                in_quotes = true;
            else if (c == ',')
            {
                out.push_back(field);
                field.clear();
            }
            else
                field.push_back(c);
        }
    }
    out.push_back(field);
    return out;
}

static bool hasMinimumInstructionColumns(const std::vector<std::string>& cols)
{
    // Current branchlog rows can arrive in a few shapes:
    // 6 columns: pc,kind,branch_target,fallthrough,tb_vaddr,bytes_or_disas
    // 7 columns: pc,kind,branch_target,fallthrough,tb_vaddr,bytes,disas
    // 8 columns: pc,kind,branch_target,fallthrough,tb_vaddr,bytes,disas,symbol
    return cols.size() >= 6;
}



std::string Emulator::disassembleInstruction(uint64_t address,
                                             std::shared_ptr<uint8_t> data, int n)
{
    (void)address;
    (void)data;
    (void)n;
    return {};
}

// Helper to check if a line is a data row (starts with 0x)
static bool isDataLine(const std::string& line) {
    std::string t = trim(line);
    return (t.size() >= 3 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'));
}

// Build/extend the line offset index incrementally
// Only scans new portions of the file - O(new_bytes) not O(total_bytes)
static void updateLineIndex(std::ifstream& f, uintmax_t currentSize, VCPUIndexState& state) {
    // File was truncated or replaced - rebuild index from scratch
    if (currentSize < state.lastIndexedSize) {
        state.lineOffsets.clear();
        state.lastIndexedOffset = 0;
        state.headerSkipped = false;
    }

    // Nothing new to index
    if (static_cast<std::streamoff>(currentSize) <= state.lastIndexedOffset) {
        return;
    }

    f.clear();
    f.seekg(state.lastIndexedOffset, std::ios::beg);

    // Handle header on first read
    if (state.lastIndexedOffset == 0 && !state.headerSkipped) {
        std::string firstLine;
        if (std::getline(f, firstLine)) {
            if (isDataLine(firstLine)) {
                // First line is data, record its offset (0)
                state.lineOffsets.push_back(0);
            }
            // else: it's a header, skip it
            state.headerSkipped = true;
        }
    }

    std::string line;
    while (f) {
        std::streamoff lineStart = f.tellg();
        if (lineStart < 0) break;

        if (!std::getline(f, line)) break;

        std::string s = trim(line);
        if (s.empty()) continue;

        auto cols = parse_csv(s);
        if (!hasMinimumInstructionColumns(cols)) continue;

        if (isDataLine(s)) {
            state.lineOffsets.push_back(lineStart);
        }
    }

    state.lastIndexedOffset = static_cast<std::streamoff>(currentSize);
    state.lastIndexedSize = currentSize;
}

// Parse a single line into InstructionInfo
static InstructionInfo parseLine(const std::string& line) {
    auto cols = parse_csv(line);

    uint64_t pc = parse_hex(cols[0]);
    std::string disType = trim(cols[1]);
    uint64_t bt = parse_hex(cols[2]);
    uint64_t ft = parse_hex(cols[3]);

    std::string dis;
    std::string symbol;
    if (cols.size() >= 8) {
        dis = trim(cols[6]);
        symbol = trim(cols[7]);
    } else if (cols.size() == 7) {
        dis = trim(cols[6]);
        symbol.clear();
        if (dis.empty()) {
            dis = trim(cols[5]);
        }
    } else if (cols.size() == 6) {
        dis = trim(cols[5]);
        symbol.clear();
    } else {
        dis.clear();
        symbol.clear();
    }

    if (disType.empty()) {
        size_t i = 0;
        while (i < dis.size() && std::isspace((unsigned char)dis[i])) ++i;
        size_t j = i;
        while (j < dis.size() && !std::isspace((unsigned char)dis[j])) ++j;
        std::string m = dis.substr(i, j - i);
        for (char &c : m) c = (char)std::tolower((unsigned char)c);

        if (m == "ret" || m == "retq" || m == "retn" || m == "iret") disType = "ret";
        else if (m == "jmp" || m == "ljmp") disType = "jmp";
        else if (m == "call" || m == "callq" || m == "lcall") disType = "call";
        else if (!m.empty() && m[0] == 'j' && m != "jmp") disType = "cond";
        else disType = "other";
    }

    return InstructionInfo(std::move(dis), std::move(disType), std::move(symbol), pc, bt, ft, bt ? 1u : 0u);
}

std::vector<InstructionInfo>* Emulator::getRunInstructions(
    int start_line,
    int n,
    bool* updated,
    int* total_lines_out
) {
    int vcpuId = getSelectedVCPU();
    std::filesystem::path kCsvPath = std::filesystem::temp_directory_path() / ("branchlog" + std::to_string(vcpuId) + ".csv");

    
    // Get or create per-VCPU state
    VCPUIndexState& state = vcpuIndexStates[vcpuId];

    // ---------- file state ----------
    std::error_code ec;
    auto sz = std::filesystem::file_size(kCsvPath, ec);
    if (ec) sz = 0;

    // Check if file changed (new data available)
    const bool file_changed = (sz != state.cachedSize);
    const bool request_unchanged = (state.cachedStart == start_line && state.cachedN == n);

    // Only skip if BOTH file unchanged AND request unchanged
    if (!file_changed && request_unchanged) {
        if (updated) *updated = false;
        if (total_lines_out) *total_lines_out = static_cast<int>(state.lineOffsets.size());
        return &instructionInfo;
    }

    // File changed or request changed - report update
    if (updated) *updated = true;

    std::ifstream f(kCsvPath, std::ios::in | std::ios::binary);
    if (!f) {
        instructionInfo.clear();
        state.lineOffsets.clear();
        state.lastIndexedOffset = 0;
        state.lastIndexedSize = 0;
        state.headerSkipped = false;
        state.cachedStart = start_line;
        state.cachedN = n;
        state.cachedSize = 0;
        if (total_lines_out) *total_lines_out = 0;
        return &instructionInfo;
    }

    // Update line index incrementally - O(new_bytes) only
    updateLineIndex(f, sz, state);

    int total_lines = static_cast<int>(state.lineOffsets.size());
    if (total_lines_out) *total_lines_out = total_lines;

    // If request is the same and current window data is still valid,
    // we can skip re-reading the lines (but we already reported updated=true above)
    if (request_unchanged && start_line + n <= total_lines && !instructionInfo.empty()) {
        state.cachedSize = sz;
        return &instructionInfo;
    }

    // Need to re-read the requested lines
    instructionInfo.clear();

    // Seek directly to start_line and read only n lines - O(n)
    if (start_line < total_lines) {
        f.clear();
        f.seekg(state.lineOffsets[start_line], std::ios::beg);

        std::string line;
        int count = 0;
        int lineIdx = start_line;

        while (std::getline(f, line) && (n <= 0 || count < n) && lineIdx < total_lines) {
            std::string s = trim(line);
            if (s.empty()) continue;

            auto cols = parse_csv(s);
            if (!hasMinimumInstructionColumns(cols)) continue;
            if (!isDataLine(s)) continue;

            instructionInfo.push_back(parseLine(line));
            ++count;
            ++lineIdx;
        }
    }

    state.cachedStart = start_line;
    state.cachedN = n;
    state.cachedSize = sz;

    return &instructionInfo;
}
