// ============================================================
// EXAMPLE: Refactored main.cpp using centralized AppState
// This is a sketch - adapt to your needs
// ============================================================

#include <cstdint>
#include <vector>
#include <string>
#include <memory>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "appstate.hpp"
#include "memorydisplay.hpp"
#include "cligui.hpp"
#include "notes.hpp"
#include "disasmdisplay.hpp"
#include "emulatorAPI.hpp"
#include "registerdisplay.hpp"
#include "iodisplay.hpp"
#include "cpupicker.hpp"
#include "assemblerdisplay.hpp"

using namespace ftxui;

int main(int argc, char** argv) {
    CLI::App app{"Scallop Shell - Debugger"};
    argv = app.ensure_utf8(argv);

    std::string targetBinaryName = ".";
    std::string arch = "x86_64";
    bool system = false;
    app.add_option("-f,--file", targetBinaryName, "Binary to debug")->required();
    app.add_option("-a,--arch", arch, "Target Architecture");
    app.add_option("-s,--system", system, "Is system?");

    CLI11_PARSE(app, argc, argv);

    // ===== Create shared state =====
    auto state = std::make_shared<ScallopUI::AppState>();

    auto screen = ScreenInteractive::Fullscreen();
    state->screen = &screen;

    // Init emulator
    Emulator emu;
    int pid = emu.startEmulation(targetBinaryName, arch);
    if (pid < 0) {
        std::cerr << "Failed to start QEMU\n";
    }

    ScallopUI::initCliCommands();

    // ===== Create components, storing refs in state =====
    const int memoryRange = 320*4;

    // Using AppState-aware components
    state->memory = ScallopUI::MemoryDisplayWithState(state, "rsp", memoryRange, 0, 8);
    state->code = ScallopUI::MemoryDisplayWithState(state, "rip", memoryRange, 0, 8);
    state->notes = ScallopUI::Notepad();
    state->cpuPicker = ScallopUI::cpuPicker();
    state->registers = ScallopUI::RegisterDisplay();
    state->ioOutput = ScallopUI::ioDisplay();
    state->disasm = ScallopUI::DisasmDisplay(state);
    state->cliInput = ScallopUI::InputCli();
    state->assembler = ScallopUI::AssemblerDisplay(arch);

    auto cli_history = ScallopUI::CliHistory();

    // ===== Build layout (same as before, but using state->* for sizes) =====
    auto tab_toggle = Toggle(&state->tabNames, &state->selectedTab);
    auto tab_container = Container::Tab(
        {state->memory, state->code, state->notes, state->cpuPicker},
        &state->selectedTab
    );

    auto left_stack = Container::Vertical({tab_toggle, tab_container});
    auto left_render = Renderer(left_stack, [&] {
        return vbox({
            tab_toggle->Render(),
            separator(),
            tab_container->Render(),
        }) | border;
    });

    auto middle_render = Renderer(state->disasm, [&] {
        return state->disasm->Render();
    });

    auto leftAndMiddle = ResizableSplitLeft(left_render, middle_render, &state->disasmSplitSize);

    auto right_tab_toggle = Toggle(&state->rightTabNames, &state->selectedRightTab);
    auto right_tab_container = Container::Tab(
        {state->registers, state->assembler},
        &state->selectedRightTab
    );
    auto right_stack = Container::Vertical({right_tab_toggle, right_tab_container});
    auto right_render = Renderer(right_stack, [&] {
        return vbox({
            right_tab_toggle->Render(),
            separator(),
            right_tab_container->Render(),
        }) | border;
    });

    auto centerTop = ResizableSplitLeft(leftAndMiddle, right_render, &state->registerSplitSize);

    auto cli_split = ResizableSplitTop(state->cliInput, cli_history, &state->cliHistorySplitSize);
    auto cli_io_split = ResizableSplitRight(state->ioOutput, cli_split, &state->ioSplitSize);

    auto mainContent = ResizableSplitBottom(cli_io_split, centerTop, &state->cliSplitSize);

    // ===== Wrap with modal container =====
    auto root = ScallopUI::ModalContainer(state, mainContent);

    // ===== Global keybindings =====
    root = CatchEvent(root, [&](const Event& e) {
        // Don't process global keys if modal is open
        if (state->hasModal()) return false;

        // Mouse-to-focus routing based on split positions.
        // This prevents a previously focused pane from stealing mouse events.
        if (e.is_mouse()) {
            auto m = const_cast<ftxui::Event&>(e).mouse();
            const int x = m.x;
            const int y = m.y;

            const int dimx = state->screen ? state->screen->dimx() : 0;
            const int dimy = state->screen ? state->screen->dimy() : 0;

            // Avoid routing focus in the bottom region; let CLI/IO handle hover.
            // The split sizes here are tricky, and the local components already do this well.
            if (dimy > 0 && y >= dimy - state->cliSplitSize - 2) {
                return false;
            }

            // Top pane: centerTop = ResizableSplitLeft(leftAndMiddle, right, &registerSplitSize)
            // Left area width is registerSplitSize; within it, disasmSplitSize divides tabs vs disasm.
            const int left_area_boundary = state->registerSplitSize;
            if (x < left_area_boundary) {
                if (x < state->disasmSplitSize) {
                    switch (state->selectedTab) {
                        case 0: state->focusPane(ScallopUI::AppState::Pane::Memory); break;
                        case 1: state->focusPane(ScallopUI::AppState::Pane::Code); break;
                        case 2: state->focusPane(ScallopUI::AppState::Pane::Notes); break;
                        case 3: state->focusPane(ScallopUI::AppState::Pane::CPU); break;
                        default: break;
                    }
                } else {
                    state->focusPane(ScallopUI::AppState::Pane::Disasm);
                }
            } else {
                if (state->selectedRightTab == 1) {
                    state->focusPane(ScallopUI::AppState::Pane::Assembler);
                } else {
                    state->focusPane(ScallopUI::AppState::Pane::Registers);
                }
            }
            // Don't consume the mouse event; children still need it.
            return false;
        }

        // Focus shortcuts
        if (e == Event::CtrlX) {
            state->focusPane(ScallopUI::AppState::Pane::CLI);
            return true;
        }
        if (e == Event::CtrlD) {
            state->focusPane(ScallopUI::AppState::Pane::Disasm);
            return true;
        }
        if (e == Event::CtrlA) {
            state->focusPane(ScallopUI::AppState::Pane::Memory);
            return true;
        }
        if (e == Event::CtrlM) {
            state->focusPane(ScallopUI::AppState::Pane::Code);
            return true;
        }
        if (e == Event::CtrlI) {
            state->focusPane(ScallopUI::AppState::Pane::IO);
            return true;
        }

        // Ctrl+F is handled by individual components (e.g., MemoryDisplay goto bar)

        return false;
    });

    // ===== Refresh thread =====
    std::atomic<bool> running = true;
    std::thread([&] {
        while (running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            screen.PostEvent(Event::Custom);
        }
    }).detach();

    // ===== Start =====
    state->focusPane(ScallopUI::AppState::Pane::CLI);
    screen.Loop(root);

    running = false;
    return 0;
}
