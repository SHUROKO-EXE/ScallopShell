#include "decompilerAPI/boxedHandlerGenerator.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <cstdint>

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFObjectFile.h"

// Defined in memory.cpp
std::vector<uint8_t> relocateX64Chunk(const std::vector<uint8_t>& bytes,
                                       uint64_t oldBase, uint64_t newBase);

namespace {

struct SymbolLocation {
    uint64_t offsetInSection;
    uint64_t size;
    const char* sectionStart; // points into the owning object buffer
    uint64_t sectionSize;
};

SymbolLocation locateSymbol(llvm::object::ObjectFile* obj, const std::string& name) {
    for (const auto& sym : obj->symbols()) {
        auto nameOrErr = sym.getName();
        if (!nameOrErr) continue;
        if (*nameOrErr != name && *nameOrErr != ("_" + name)) continue;

        auto addrOrErr = sym.getAddress();
        if (!addrOrErr) continue;

        uint64_t symSize = 0;
        if (llvm::isa<llvm::object::ELFObjectFileBase>(obj)) {
            llvm::object::ELFSymbolRef elfSym(sym);
            symSize = elfSym.getSize();
        }

        auto secOrErr = sym.getSection();
        if (!secOrErr || *secOrErr == obj->section_end()) continue;

        auto contentsOrErr = (*secOrErr)->getContents();
        if (!contentsOrErr) continue;

        llvm::StringRef secData = *contentsOrErr;
        uint64_t secAddr = (*secOrErr)->getAddress();

        return {*addrOrErr - secAddr, symSize, secData.data(), secData.size()};
    }
    throw std::runtime_error("Symbol not found: " + name);
}

} // namespace

std::vector<uint8_t> emitBoxedHandler(
    const std::string& targetTriple,
    uint64_t stubAddr,
    uint64_t counterAddr,
    const std::vector<VariantChunk>& variantChunks,
    uint64_t continuationAddr) {

    // TODO: move to a one-time init
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmPrinters();
    llvm::InitializeAllAsmParsers();

    std::string error;
    const llvm::Target* target = llvm::TargetRegistry::lookupTarget(targetTriple, error);
    if (!target)
        throw std::runtime_error("LLVM target lookup failed: " + error);

    llvm::TargetOptions opt;
    auto targetMachine = std::unique_ptr<llvm::TargetMachine>(
        target->createTargetMachine(
            targetTriple, "generic", "", opt, llvm::Reloc::Static,
            llvm::CodeModel::Small, llvm::CodeGenOptLevel::Default));
    if (!targetMachine)
        throw std::runtime_error("Failed to create LLVM TargetMachine");

    llvm::LLVMContext context;
    auto module = std::make_unique<llvm::Module>("scallop_boxed_handler", context);
    module->setTargetTriple(targetTriple);
    module->setDataLayout(targetMachine->createDataLayout());

    llvm::IRBuilder<> builder(context);
    auto* i64    = builder.getInt64Ty();
    auto* i64ptr = llvm::PointerType::getUnqual(i64);
    auto* voidTy = builder.getVoidTy();
    auto* blobTy = llvm::FunctionType::get(voidTy, {}, false);
    auto* fnType = llvm::FunctionType::get(voidTy, {}, false);
    auto* fn = llvm::Function::Create(fnType, llvm::Function::ExternalLinkage,
                                      "scallop_boxed_handler", module.get());
    // NoReturn prevents LLVM from generating a prologue/epilogue, which would
    // shift RSP and break the register save/restore symmetry below.
    fn->addFnAttr(llvm::Attribute::NoReturn);

    auto* entry = llvm::BasicBlock::Create(context, "entry", fn);
    builder.SetInsertPoint(entry);

    const bool isX86_64 = (targetTriple.rfind("x86_64", 0) == 0);

    // x86-64: save the registers the counter machinery will clobber (rax, rcx,
    // rdx) plus flags, so variant bytes execute with the original CPU state.
    // The matching restore is emitted at the start of each case block.
    if (isX86_64) {
        auto* saveAsm = llvm::InlineAsm::get(blobTy,
            "pushfq\npush %rdx\npush %rcx\npush %rax\n",
            "~{rax},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags},~{memory}",
            /*hasSideEffects=*/true);
        builder.CreateCall(saveAsm);
    }

    // Counter: load pre-increment value, then store incremented value
    llvm::Value* counterPtr = builder.CreateIntToPtr(
        builder.getInt64(counterAddr), i64ptr, "counter_ptr");
    llvm::Value* idx  = builder.CreateLoad(i64, counterPtr, "idx");
    llvm::Value* next = builder.CreateAdd(idx, builder.getInt64(1), "next");
    builder.CreateStore(next, counterPtr);

    // Allocate one basic block per variant
    std::vector<llvm::BasicBlock*> caseBlocks;
    caseBlocks.reserve(variantChunks.size());
    for (size_t i = 0; i < variantChunks.size(); ++i)
        caseBlocks.push_back(llvm::BasicBlock::Create(context, "case", fn));

    // Compare chain: if idx == 0 goto case[0], idx == 1 goto case[1], ...
    // The last case is the default (no compare needed).
    for (size_t i = 0; i + 1 < variantChunks.size(); ++i) {
        llvm::Value* cmp = builder.CreateICmpEQ(idx, builder.getInt64(i));
        auto* chk = llvm::BasicBlock::Create(context, "chk", fn);
        builder.CreateCondBr(cmp, caseBlocks[i], chk);
        builder.SetInsertPoint(chk);
    }
    builder.CreateBr(caseBlocks.back());

    // Case blocks: restore registers, then emit a globally-visible label
    // followed by NOP placeholders for:
    //   [variant bytes]  — patched with relocated variant in second pass
    //   [5 bytes]        — patched with jmp continuationAddr (x86-64) in second pass
    for (size_t i = 0; i < variantChunks.size(); ++i) {
        builder.SetInsertPoint(caseBlocks[i]);

        // x86-64: restore original register state before variant bytes execute
        if (isX86_64) {
            auto* restoreAsm = llvm::InlineAsm::get(blobTy,
                "pop %rax\npop %rcx\npop %rdx\npopfq\n",
                "~{rax},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags},~{memory}",
                /*hasSideEffects=*/true);
            builder.CreateCall(restoreAsm);
        }

        std::string asmStr = ".globl scallop_case_" + std::to_string(i) + "\n"
                           + "scallop_case_" + std::to_string(i) + ":\n";
        // variant bytes + 5-byte continuation jmp, all as NOP placeholders
        const size_t nopCount = variantChunks[i].bytes.size() + 5;
        if (nopCount > 0) {
            asmStr += ".byte ";
            for (size_t j = 0; j < nopCount; ++j) {
                if (j > 0) asmStr += ", ";
                asmStr += "0x90";
            }
        }

        auto* blob = llvm::InlineAsm::get(blobTy, asmStr, "", /*hasSideEffects=*/true);
        builder.CreateCall(blob, {});
        builder.CreateUnreachable();
    }

    // Compile to an in-memory buffer
    llvm::SmallVector<char> objBuffer;
    {
        llvm::raw_svector_ostream objStream(objBuffer);
        llvm::legacy::PassManager pm;
        if (targetMachine->addPassesToEmitFile(pm, objStream, nullptr,
                                               llvm::CodeGenFileType::ObjectFile))
            throw std::runtime_error("LLVM TargetMachine cannot emit object file");
        pm.run(*module);
    }

    // Parse the object to find where each symbol landed in the section
    llvm::MemoryBufferRef bufRef(
        llvm::StringRef(objBuffer.data(), objBuffer.size()), "scallop_boxed_handler");
    auto objOrErr = llvm::object::ObjectFile::createObjectFile(bufRef);
    if (!objOrErr)
        throw std::runtime_error("Failed to parse object: " +
                                 llvm::toString(objOrErr.takeError()));
    llvm::object::ObjectFile* obj = objOrErr->get();

    auto funcLoc = locateSymbol(obj, "scallop_boxed_handler");
    if (funcLoc.size == 0)
        funcLoc.size = funcLoc.sectionSize - funcLoc.offsetInSection;

    // Second pass: patch variant bytes and continuation jmp into each case block.
    for (size_t i = 0; i < variantChunks.size(); ++i) {
        auto caseLoc = locateSymbol(obj, "scallop_case_" + std::to_string(i));

        // Where this variant blob will actually live in the target binary
        const uint64_t variantAddr =
            stubAddr + (caseLoc.offsetInSection - funcLoc.offsetInSection);

        std::vector<uint8_t> relocated = variantChunks[i].bytes;
        if (isX86_64 && variantChunks[i].start_pc != variantAddr) {
            relocated = relocateX64Chunk(variantChunks[i].bytes,
                                         variantChunks[i].start_pc, variantAddr);
        }

        // Bounds check covers variant bytes + 5-byte continuation jmp placeholder
        const size_t patchOffset = (caseLoc.sectionStart - objBuffer.data())
                                 + caseLoc.offsetInSection;
        if (patchOffset + relocated.size() + 5 > objBuffer.size())
            throw std::runtime_error("Patch out of bounds for scallop_case_" +
                                     std::to_string(i));

        // Patch variant bytes
        std::copy(relocated.begin(), relocated.end(),
                  objBuffer.begin() + static_cast<ptrdiff_t>(patchOffset));

        // x86-64: patch continuation jmp (E9 + rel32) immediately after variant bytes.
        // For variants that end with an explicit branch/ret this jmp is dead code.
        // For fall-through variants it provides the required continuation.
        if (isX86_64 && continuationAddr != 0) {
            const uint64_t jmpSrc = variantAddr + relocated.size();
            const int64_t disp = static_cast<int64_t>(continuationAddr)
                               - static_cast<int64_t>(jmpSrc + 5);
            if (disp >= INT32_MIN && disp <= INT32_MAX) {
                const uint32_t d = static_cast<uint32_t>(disp);
                uint8_t* p = reinterpret_cast<uint8_t*>(
                    objBuffer.data() + patchOffset + relocated.size());
                p[0] = 0xE9;
                p[1] = d & 0xFF;
                p[2] = (d >> 8) & 0xFF;
                p[3] = (d >> 16) & 0xFF;
                p[4] = (d >> 24) & 0xFF;
            }
        }
    }

    // Extract the final patched function bytes
    const size_t extractOffset = (funcLoc.sectionStart - objBuffer.data())
                                + funcLoc.offsetInSection;
    if (extractOffset + funcLoc.size > objBuffer.size())
        throw std::runtime_error("Function bytes out of bounds in object");

    const uint8_t* start = reinterpret_cast<const uint8_t*>(
        objBuffer.data() + extractOffset);
    return std::vector<uint8_t>(start, start + funcLoc.size);
}
