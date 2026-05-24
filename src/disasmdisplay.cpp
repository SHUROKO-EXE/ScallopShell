#include "disasmdisplay.hpp"
#include "emulatorAPI.hpp"

#include <unordered_map>
#include <filesystem>

using namespace ftxui;

namespace ScallopUI {


    Component DisasmDisplay(AppStatePtr state) {
        class Impl : public ComponentBase {
        private:
            int rows;
            int currentTopRow = 0;
            int min_top = 37;
            int instructionCount = 0;
            int maxTopRow = 0;
            Box renderedArea;         
            bool follow_tail = true; 
            int totalLines = 0;
            int lastTotalLines = 0;  
            std::vector<Box> rowBoxes;
            std::vector<Box> checkboxBoxes;
            std::vector<uint64_t> rowAddresses;
            std::unordered_map<uint64_t, Breakpoint> breakpoints;
            bool breakpointsLoaded = false;
            int lastBreakpointVcpu = -1;
            std::filesystem::path lastBreakpointPath;
            std::filesystem::file_time_type lastBreakpointMtime{};
            std::string pythonScriptPath = "";
            bool autopatch = false;
            bool showInputModal_ = false;
            std::string inputBuffer_;
            bool lastBreakpointMtimeValid = false;
            uint64_t lastBaseAddress = 0;
            bool showSymbols_ = true;
            Box symButtonBox_;
            AppStatePtr state_;

            void setBreakpoint(uint64_t address, bool enabled) {
                if (enabled) {
                    const bool currentAutopatch = state_ ? state_->autopatch : autopatch;
                    // Only send to the backend when the breakpoint is newly enabled.
                    if (!breakpoints.contains(address)) {
                        Emulator::addBreakpoint(address, currentAutopatch, pythonScriptPath);
                    }
                    breakpoints[address] = {address, currentAutopatch, !pythonScriptPath.empty()};
                    return;
                }

                // We currently don't have a removeBreakpoint API, so just clear locally.
                Emulator::deleteBreakpoint(address);
                breakpoints.erase(address);
            }

            bool Focusable() const override { return true; }

            bool OnEvent(Event e) override {

                if (showInputModal_) {
                    if (e == Event::Escape) {
                        showInputModal_ = false;
                        return true;
                    }
                    if (e == Event::Return) {
                        pythonScriptPath = inputBuffer_;
                        showInputModal_ = false;
                        return true;
                    }
                    if (e == Event::Backspace) {
                        if (!inputBuffer_.empty()) inputBuffer_.pop_back();
                        return true;
                    }
                    if (e.is_character()) {
                        inputBuffer_ += e.character();
                        return true;
                    }
                    return true;
                }

                if (e == Event::ArrowUp) {
                    if (currentTopRow > 0) currentTopRow--;
                    follow_tail = false;
                    return true;
                }

                if (Focused() && (e == Event::CtrlB)) {
                    inputBuffer_ = pythonScriptPath;
                    showInputModal_ = true;
                    return true;
                }

                if (e == Event::PageUp) {
                    currentTopRow = std::max(0, currentTopRow - min_top);
                    follow_tail = false;
                    return true;
                }

                if (e == Event::ArrowDown) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    if (currentTopRow < maxTopRow) currentTopRow++;
                    if (currentTopRow >= maxTopRow) follow_tail = true; // user came back to bottom
                    return true;
                }

                if (e == Event::PageDown) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    currentTopRow = std::min(maxTopRow, currentTopRow + min_top);
                    if (currentTopRow >= maxTopRow) follow_tail = true;
                    return true;
                }
                if (e == Event::g) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    currentTopRow = maxTopRow;
                    follow_tail = true;
                    return true;
                }

                // Hover-to-focus
                if (e.is_mouse()) {
                    const auto& m = e.mouse();
                    const bool inRenderedArea = renderedArea.Contain(m.x, m.y);
                    const bool inDisasmPaneBySplit =
                        state_ ? (m.x >= state_->disasmSplitSize) : true;

                    if (!(inRenderedArea && inDisasmPaneBySplit)) {
                        return false;  // Don't steal mouse events from other panes.
                    }

                    // Only handle explicit checkbox clicks; otherwise let other panes react.
                    // Use Released to avoid toggling twice (Pressed + Released).
                    if (m.button == Mouse::Left && m.motion == Mouse::Released) {
                        if (symButtonBox_.Contain(m.x, m.y)) {
                            showSymbols_ = !showSymbols_;
                            return true;
                        }
                        for (int i = 0; i < instructionCount &&
                                        i < static_cast<int>(checkboxBoxes.size()); ++i) {
                            if (!checkboxBoxes[i].Contain(m.x, m.y)) continue;
                            if (i >= static_cast<int>(rowAddresses.size())) return true;
                            const auto address = rowAddresses[static_cast<size_t>(i)];
                            const bool enabled = !breakpoints.contains(address);
                            setBreakpoint(address, enabled);
                            return true;
                        }
                    }

                    if (Focused() && m.button == ftxui::Mouse::WheelUp) {
                        if (currentTopRow > 0) currentTopRow--;
                        follow_tail = false;
                        return true;
                    }
                    if (Focused() && m.button == ftxui::Mouse::WheelDown) {
                        int maxTopRow = std::max(0, totalLines - min_top);
                        if (currentTopRow < maxTopRow) currentTopRow++;
                        if (currentTopRow >= maxTopRow) follow_tail = true; // user came back to bottom
                        return true;
                    }

                    return false;
                }

                return ComponentBase::OnEvent(e); // forward anything else

            }

            Element OnRender() override {

                std::vector<Element> lines;
                static bool hasUpdated = 0;
                
            
                const std::vector<InstructionInfo>* assemblyInstructions = Emulator::getRunInstructions(currentTopRow, min_top, &hasUpdated, &totalLines);
                const int currentVcpu = Emulator::getSelectedVCPU();
                const std::filesystem::path cfgPath = Emulator::getBreakpointConfigPath(currentVcpu);
                bool configChanged = false;
                const uint64_t baseAddress = Emulator::getRuntimeBaseAddress();
                if (baseAddress != lastBaseAddress) {
                    lastBaseAddress = baseAddress;
                    configChanged = true;
                }
                if (cfgPath != lastBreakpointPath) {
                    lastBreakpointPath = cfgPath;
                    lastBreakpointMtimeValid = false;
                    configChanged = true;
                }
                if (!cfgPath.empty()) {
                    std::error_code ec;
                    auto mtime = std::filesystem::last_write_time(cfgPath, ec);
                    if (!ec) {
                        if (!lastBreakpointMtimeValid || mtime != lastBreakpointMtime) {
                            lastBreakpointMtime = mtime;
                            lastBreakpointMtimeValid = true;
                            configChanged = true;
                        }
                    }
                }

                if (!breakpointsLoaded || hasUpdated || currentVcpu != lastBreakpointVcpu || configChanged) {
                    auto prevBreakpoints = breakpoints;
                    breakpoints.clear();
                    for (const Breakpoint& bp : Emulator::getBreakpointsFromConfig(currentVcpu)) {
                        auto it = prevBreakpoints.find(bp.address);
                        bool hasPython = bp.hasPythonScriptExec ||
                                         (it != prevBreakpoints.end() && it->second.hasPythonScriptExec);
                        breakpoints[bp.address] = {bp.address, bp.autopatch, hasPython};
                    }
                    breakpointsLoaded = true;
                    lastBreakpointVcpu = currentVcpu;
                }

                instructionCount = assemblyInstructions->size();
                maxTopRow = std::max(0, totalLines - min_top);
                rowBoxes.assign(static_cast<size_t>(instructionCount), {});
                checkboxBoxes.assign(static_cast<size_t>(instructionCount), {});
                rowAddresses.assign(static_cast<size_t>(instructionCount), 0);

                auto at_bottom = [&]{
                    int slack = 0;
                    return currentTopRow >= std::max(0, maxTopRow - slack);
                };

                if (hasUpdated) {
                    // If the user was at bottom, keep them at bottom.
                    // Also: if this is first load, follow tail.
                    if (follow_tail || at_bottom()) {
                        currentTopRow = maxTopRow;
                        follow_tail = true;
                    }
                }
                lastTotalLines = totalLines;
                
                auto symBtn = hbox({text("Symbols: "), text(showSymbols_ ? "[X]" : "[ ]") | reflect(symButtonBox_)});
                auto header = hbox({text("  Disassembly "), text("  Base Addr:" + hex8ByteStr(Emulator::getRuntimeBaseAddress())), text("      Ctrl+B for Python Break.")})
                    | underlined | dim | bold | color(Color::CornflowerBlue);
                auto headerLine = hbox({header, filler(), symBtn});
                lines.push_back(headerLine);

                size_t maxInstrLen = 0;
                for (int r = 0; r < instructionCount; r++)
                    maxInstrLen = std::max(maxInstrLen, assemblyInstructions->at(r).instruction.size());

                for (int r = 0; r < instructionCount; r++) {
                    const auto& info = assemblyInstructions->at(r);
                    rowAddresses[static_cast<size_t>(r)] = info.address;
                    const bool hasBreakpoint = breakpoints.contains(info.address);
                    const bool checked = hasBreakpoint;

                    Element checkbox = text(checked ? "[x] " : "[ ] ")
                        | reflect(checkboxBoxes[r]);

                    if (checked) {
                        checkbox | color(Color::GrayDark);
                    }
                    else {
                        checkbox | color(Color::Red1);
                    }

                    auto disasmColor = color(Color::Magenta);

                    bool isPythonScript = hasBreakpoint && breakpoints.at(info.address).hasPythonScriptExec;
                    if (hasBreakpoint) {
                        if (isPythonScript)
                            disasmColor = color(Color::Blue1);
                        else
                            disasmColor = color(Color::Red1);
                    }
                    else if (info.instructionType == "other")
                        disasmColor = color(Color::Magenta);
                    else if (info.instructionType == "jmp")
                        disasmColor = color(Color::Yellow1);
                    else if (info.instructionType == "call")
                        disasmColor = color(Color::Yellow1);
                    else if (info.instructionType == "cond")
                        disasmColor = color(Color::Orange1);
                    else if (info.instructionType == "ret")
                        disasmColor = color(Color::MediumPurple1);

                    size_t gap = maxInstrLen + 5 - info.instruction.size();
                    std::string arrowStr = (!showSymbols_ || info.symbol.empty()) ? std::string(gap + 1, ' ') : "  <" + std::string(gap - 3, '-') + " ";

                    auto instrColor = hasBreakpoint ? (isPythonScript ? color(Color::Blue1) : color(Color::Red1)) : color(Color::CornflowerBlue);
                    Element left = hbox({
                        text(hex8ByteStr(info.address)) | disasmColor,
                        text(" - " + info.instruction) | instrColor,
                        text(arrowStr) | color(Color::GrayLight),
                    });

                    Element right = text(showSymbols_ ? info.symbol : "") | color(Color::Magenta);

                    Element row = hbox({checkbox, left, right}) | reflect(rowBoxes[r]);
                    if (hasBreakpoint) {
                        row = row | color(Color::White);
                    }
                    lines.emplace_back(row);

                    }

                    auto display = vbox(lines) | border | focus | reflect(renderedArea);

                    if (Focused())
                        display = display | color(Color::Magenta);

                    if (showInputModal_) {
                        auto cursor = text(inputBuffer_ + "▋") | color(Color::CornflowerBlue);
                        auto modal_box = vbox({
                            text(" Set Python Script Path ") | bold | center,
                            separator(),
                            hbox({text(" > ") | color(Color::Cyan), cursor}) | border,
                            text(" Enter: confirm  ·  Esc: cancel ") | dim | center,
                        }) | border | bgcolor(Color::Black) | color(Color::CornflowerBlue);
                        return dbox({display, modal_box | vcenter | hcenter | clear_under});
                    }

                    return display;
                }

        
        public:

            explicit Impl(AppStatePtr state) : state_(std::move(state)) {}

            

        };

        return Make<Impl>(std::move(state));
    }
}
