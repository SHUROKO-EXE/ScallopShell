#pragma once

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <functional>
#include <memory>
#include <string>
#include <stack>
#include <vector>

namespace ScallopUI {

// Forward declare
struct AppState;

// Modal definition - a component + its cleanup callback
struct Modal {
    ftxui::Component component;
    std::function<void()> onClose;
    std::string id;  // For debugging/logging
};

// Central UI state - passed to all components via shared_ptr
struct AppState {
    // ===== Screen reference (for PostEvent, Exit) =====
    ftxui::ScreenInteractive* screen = nullptr;

    // ===== Tab/Pane state =====
    int selectedTab = 0;
    std::vector<std::string> tabNames = {"memory", "code", "notepad", "cpu"};
    int selectedRightTab = 0;
    std::vector<std::string> rightTabNames = {"registers", "assembler"};

    // ===== Split sizes (persisted across renders) =====
    int disasmSplitSize = 44;
    int registerSplitSize = 160;
    int cliSplitSize = 10;
    int ioSplitSize = 150;
    int cliHistorySplitSize = 5;

    // ===== Modal stack =====
    std::vector<Modal> modals;

    bool hasModal() const { return !modals.empty(); }

    void pushModal(const std::string& id, ftxui::Component comp, std::function<void()> onClose = nullptr) {
        modals.push_back({comp, onClose, id});
        comp->TakeFocus();
    }

    void popModal() {
        if (!modals.empty()) {
            if (modals.back().onClose) {
                modals.back().onClose();
            }
            modals.pop_back();
        }
    }

    void closeModal(const std::string& id) {
        for (auto it = modals.begin(); it != modals.end(); ++it) {
            if (it->id == id) {
                if (it->onClose) it->onClose();
                modals.erase(it);
                return;
            }
        }
    }

    // ===== Focus tracking =====
    enum class Pane { CLI, Disasm, Memory, Code, Registers, IO, Notes, CPU, Assembler };
    Pane lastFocusedPane = Pane::CLI;

    // Store component refs for focus restoration after modal close
    ftxui::Component cliInput;
    ftxui::Component disasm;
    ftxui::Component memory;
    ftxui::Component code;
    ftxui::Component registers;
    ftxui::Component ioOutput;
    ftxui::Component notes;
    ftxui::Component cpuPicker;
    ftxui::Component assembler;

    ftxui::Component getPaneComponent(Pane p) {
        switch (p) {
            case Pane::CLI: return cliInput;
            case Pane::Disasm: return disasm;
            case Pane::Memory: return memory;
            case Pane::Code: return code;
            case Pane::Registers: return registers;
            case Pane::IO: return ioOutput;
            case Pane::Notes: return notes;
            case Pane::CPU: return cpuPicker;
            case Pane::Assembler: return assembler;
        }
        return nullptr;
    }

    void focusPane(Pane p) {
        lastFocusedPane = p;
        auto comp = getPaneComponent(p);
        if (comp) comp->TakeFocus();
    }

    void restoreFocus() {
        focusPane(lastFocusedPane);
    }

    // ===== Emulator state (could move more here) =====
    bool emulatorRunning = false;
    bool autopatch = false;
};

using AppStatePtr = std::shared_ptr<AppState>;

// ===== Helper: Create a modal-aware root component =====
// This wraps your main content and handles modal stacking
inline ftxui::Component ModalContainer(AppStatePtr state, ftxui::Component mainContent) {
    using namespace ftxui;

    return Renderer(mainContent, [=] {
        Elements layers;
        layers.push_back(mainContent->Render());

        // Render modals on top with dimmed background
        for (const auto& modal : state->modals) {
            layers.push_back(
                dbox({
                    // Dim overlay - semi-transparent dark
                    filler() | dim,
                    // Centered modal - no border, transparent background
                    modal.component->Render() | center,
                })
            );
        }

        return dbox(layers);
    }) | CatchEvent([=](Event e) {
        // If modal is open, route events to it exclusively
        if (state->hasModal()) {
            // Escape closes top modal
            if (e == Event::Escape) {
                state->popModal();
                state->restoreFocus();
                return true;
            }
            // Route all other events to the top modal
            return state->modals.back().component->OnEvent(e);
        }
        return false;  // Let main content handle
    });
}

} // namespace ScallopUI
