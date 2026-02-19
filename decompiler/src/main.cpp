#include "main.hpp"
#include "csv.hpp"
#include "filter.hpp"
#include "unordered_map"
#include "decompilerAPI.hpp"
#include "CLI11.hpp"
#include <cstdlib>

int main(int argc, char** argv) {
    CLI::App app{"Scallop Shell Decompiler"};
    argv = app.ensure_utf8(argv);

    std::string targetBinaryPath;
    int vcpu = 0;
    app.add_option("-f,--file", targetBinaryPath, "Target binary path")->required();
    app.add_option("-v,--vcpu", vcpu, "VCPU index");
    CLI11_PARSE(app, argc, argv);

    std::vector<instructionData> insns;

    std::filesystem::path fileInfoPath = std::filesystem::path("/tmp") / "scallop_file_info";

    if (!writeTargetTripleFromElf(std::filesystem::path(targetBinaryPath), fileInfoPath)) {
        std::cerr << "Failed to create " << fileInfoPath << " from " << targetBinaryPath << std::endl;
        return 1;
    }

    std::string targetTriple;
    try {
        targetTriple = readTargetTriple(fileInfoPath);
        std::cout << "Target triple: " << targetTriple << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    std::filesystem::path branchlogPath =
        std::filesystem::temp_directory_path() / ("branchlog" + std::to_string(vcpu) + ".csv");

    std::ifstream branchlog(branchlogPath);
    std::string csvLine;
    while (std::getline(branchlog, csvLine)) {
        instructionData insn;
        if (parseLine(csvLine, insn) == 0) {
            insns.emplace_back(std::move(insn));
        }
    }

    std::cout << "Got lines " << std::endl;

    std::unordered_map<uint64_t, int> insnLooping;
    std::vector<uint8_t> memoryImageBytes;
    
    uint64_t base = 0;
    uint64_t entry = 0;
    uint64_t dataStart = 0;
    uint64_t dataEnd = 0;
    std::vector<ElfSymbol> symbols;
    auto image = buildMemoryImage(insns, base, entry, 0x90, targetTriple,
                                  &dataStart, &dataEnd, &symbols);

    std::cout << "Built memory image" << std::endl;
    if (!image.empty()) {
        std::filesystem::path outPath = std::filesystem::temp_directory_path() / "scallop";
        if (writeElfX64LE(outPath, image, base, entry, dataStart, dataEnd, &symbols)) {
            std::cout << "Wrote ELF to " << outPath << " (base=0x"
                      << std::hex << base << ", entry=0x" << entry << ")" << std::dec << std::endl;

            const int rc = DecompilerAPI::runDecompiler(std::filesystem::path(std::getenv("GHIDRA_DIR")) / "support" / "analyzeHeadless", outPath);
            if (rc != 0) {
                std::cerr << "analyzeHeadless exited with code " << rc << std::endl;
            }
        } else {
            std::cerr << "Failed to write ELF to " << outPath << std::endl;
        }
    }

    return 0;
}
