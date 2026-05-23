#include "memorydisplay.hpp"
#include "emulatorAPI.hpp"
#include <ftxui/component/component.hpp>
#include <utility>
#include <algorithm>
#include "debug.hpp"

using namespace ftxui;

/**
 * Pull from Emulator::getRegisters() and grep for the input string
 * @param registerArg Register to check
 */
uint64_t getRegisterValue(const std::string& registerArg) {
    std::vector<std::string>* regs = Emulator::getRegisters();
    if (!regs || regs->empty()) {
        regs = Emulator::getRegisters();
        if (!regs)
            return 0;
    }

    const std::string prefix = registerArg + "=";
    for (const std::string& line : *regs) {
        if (line.rfind(prefix, 0) != 0)
            continue;
        const char* valStr = line.c_str() + prefix.size();
        return strtoull(valStr, nullptr, 16);
    }

    return 0; // not found
}



namespace ScallopUI
{

    struct HexEditHistory {
        int row;
        int col;
        uint8_t data;

        HexEditHistory(int row_, int col_, uint8_t data_) {
            row = row_;
            col = col_;
            data = data_;
        }

    };

    /*===================================================*/

    Component MemoryDisplay(std::vector<uint8_t>* data, std::string followedReg, size_t size,
                            uint64_t base_addr, int bytesPerRow, int visibleRows)
    {
        // Use wrapper with no AppState
        return MemoryDisplayWithState(nullptr, std::move(followedReg), size, base_addr, bytesPerRow, visibleRows);
    }

    Component MemoryDisplayWithState(AppStatePtr state, std::string followedReg, size_t size,
                                      uint64_t base_addr, int bytesPerRow, int visibleRows)
    {
        class Impl : public ComponentBase
        {
        private:

        /**
         * Commit the nibble for hex editing
         */
        void commit_nibble(int v) {
            if (selectedRow < 0 || selectedColumn < 0) return;
            if (!data_ || data_->empty()) return;

            const size_t idx = (size_t)selectedRow * bpr_ + selectedColumn;
            if (idx >= data_->size()) return;

            // Always snapshot before we mutate
            hexEditHistory.emplace_back(selectedRow, selectedColumn, data_->at(idx));

            editTrail.emplace_back(selectedRow, selectedColumn);

            if (pending_nibble_ < 0) {
                // --- First nibble (high) ---
                uint8_t old = data_->at(idx);
                data_->at(idx) = (uint8_t)((v << 4) | (old & 0x0F));
                pending_nibble_ = v; // waiting for low nibble
                markMemoryDirty();
            } else {
                // --- Second nibble (low) ---
                data_->at(idx) = (uint8_t)((pending_nibble_ << 4) | v);
                pending_nibble_ = -1;
                markMemoryDirty();

                // advance selection to next cell
                if (++selectedColumn >= bpr_) {
                    selectedColumn = 0;
                    ++selectedRow;
                }
                // if we walked off the end, exit edit mode
                if ((size_t)selectedRow * bpr_ + selectedColumn >= data_->size()) {
                    editing_ = false;
                }
            }
        }

        void markMemoryDirty() {
            if (!data_ || data_->empty())
                return;
            const size_t span = std::min(size_, data_->size());
            Emulator::stageMemoryWrite(base_addr_, *data_, static_cast<int>(span));
        }


        bool handleMouseTakeover(ftxui::Mouse m, Event e) {
            // Local (x,y) inside the rendered element:
            int lx = m.x - mouseBox.x_min - leftmostX;
            int ly = m.y - mouseBox.y_min - highestY;
            // Map local coords to your data model:
            int cell_w = 3; // Each byte is 2 characters + a space
            int cell_h = 1; // one line per row

            // Account for the header row ("Address Bytes") at the top.
            // This keeps row selection aligned with the visible byte grid.
            const int header_rows = 1;
            ly -= header_rows;

            if (lx < 0 || ly < 0)
                return false;

            int col = lx / cell_w;
            int row = (ly / cell_h) + top_row_;

            selectedRow = row;
            selectedColumn = col;

            if (selectedRow < 0 || selectedRow >= rows_)
                return false;

            if (selectedColumn < 0 || selectedColumn >= bpr_)
                return false;

            // Guard against short reads near the end of memory.
            if (data_ && !data_->empty()) {
                const size_t idx = static_cast<size_t>(selectedRow) * bpr_ + selectedColumn;
                if (idx >= data_->size())
                    return false;
            }
            editing_ = true;

            return true;
        }

        // Handle the goto address/register input
        void handleGotoInput(const std::string& input) {
            if (input.empty()) return;

            // Check if it looks like a hex address (0x prefix)
            if (input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
                // It's an address - set base_addr directly and clear followedReg
                try {
                    base_addr_ = std::stoull(input, nullptr, 16);
                    followedReg_.clear();
                    cache_key_ = "addr_" + input;
                    top_row_ = 0;
                } catch (...) {
                    // Invalid address, ignore
                }
            } else if (!input.empty() && std::all_of(input.begin(), input.end(), ::isxdigit)) {
                // All hex digits - treat as hex address
                try {
                    base_addr_ = std::stoull(input, nullptr, 16);
                    followedReg_.clear();
                    cache_key_ = "addr_" + input;
                    top_row_ = 0;
                } catch (...) {
                    // Invalid, ignore
                }
            } else {
                // Assume it's a register name
                followedReg_ = input;
                cache_key_ = input;
                top_row_ = 0;
                // base_addr_ will be updated on next render
            }

            gotoMode_ = false;
            gotoInput_.clear();
        }

        public:
            Impl(AppStatePtr appState, std::string followedReg, size_t size,
                 uint64_t base_addr, int bpr, int rows)
                : state_(appState),
                  data_(nullptr),
                  size_(size ? size
                             : static_cast<size_t>(rows) * static_cast<size_t>(bpr)),
                  base_addr_(base_addr),
                  bpr_(bpr),
                  rows_(rows),
                  followedReg_(std::move(followedReg)),
                  cache_key_(followedReg_.empty() ? "default" : followedReg_)
                  {
                    shouldAutopatch = Checkbox("Autopatch", state_ ? &state_->autopatch : &autoPatch);
                    Add(shouldAutopatch);
                  }

        private:
            AppStatePtr state_;
            std::vector<uint8_t>* data_;
            size_t size_;
            uint64_t base_addr_;
            int bpr_;
            int rows_;
            int top_row_ = 0;
            ftxui::Box mouseBox; // Box where mouse can be
            int selectedRow = -1; // Where the mouse is selecting - row
            int selectedColumn = -1; // Where the mouse is selecting - column
            int leftmostX = 0x10; // Offset that accounts for the displayed memory addresses pixels
            int highestY = 1; // Offset that accounts for window border
            bool editing_ = false;           // Is editing? false = no
            int pending_nibble_ = -1;        // -1 = none, otherwise 0..15
            bool pushed_snapshot_ = false;
            std::vector<HexEditHistory> hexEditHistory;
            std::vector<std::pair<int,int>> editTrail;  // Highlights for edited bits
            std::string followedReg_;
            std::string cache_key_;
            int current_vcpu = 0;
            bool autoPatch = false;
            Component shouldAutopatch;

            // Goto mode state (inline input bar)
            bool gotoMode_ = false;
            std::string gotoInput_;

            bool Focusable() const override { return true; }

            /*====================================*/
            /*====================================*/

            // All event handling
            bool OnEvent(Event e) override
            {
                // Use actual data size if available, otherwise requested size
                const size_t actual_size = (data_ != nullptr && !data_->empty()) ? data_->size() : size_;
                const int max_rows = static_cast<int>((actual_size + bpr_ - 1) / bpr_);
                const int max_top = std::max(0, max_rows - rows_);

                // Handle goto mode input
                if (gotoMode_) {
                    if (e == Event::Escape) {
                        gotoMode_ = false;
                        gotoInput_.clear();
                        return true;
                    }
                    if (e == Event::Return) {
                        handleGotoInput(gotoInput_);
                        return true;
                    }
                    if (e == Event::Backspace && !gotoInput_.empty()) {
                        gotoInput_.pop_back();
                        return true;
                    }
                    if (e.is_character()) {
                        gotoInput_ += e.character();
                        return true;
                    }
                    return true; // Consume all events in goto mode
                }

                // Ctrl+F or '/' to enter goto mode (when focused and not editing)
                if (Focused() && !editing_ && (e == Event::CtrlF || e == Event::Character('/'))) {
                    gotoMode_ = true;
                    gotoInput_.clear();
                    return true;
                }

                // Editing keystrokes
                if (editing_) {
                    // Return commits and exits edit mode
                    if (e == Event::Return) {
                        pending_nibble_ = -1;
                        editing_ = false;
                        pushed_snapshot_ = false;
                        autoPatch = false;
                        editTrail.clear();
                        return true;
                    }
                    // Backspace "un-types" the high nibble edit (restores original if needed)
                    if (e == Event::Backspace) {
                        if (!hexEditHistory.empty() && data_ && !data_->empty()) {
                            HexEditHistory lastEdit = hexEditHistory.back();
                            size_t idx = lastEdit.row * bpr_ + lastEdit.col;
                            if (idx < data_->size()) {
                                data_->at(idx) = lastEdit.data;
                                selectedRow = lastEdit.row;
                                selectedColumn = lastEdit.col;
                            }
                            hexEditHistory.pop_back();
                        }
                        if (!editTrail.empty()) {
                            editTrail.pop_back();
                        }
                        markMemoryDirty();
                        return true;
                    }

                    // Hex characters
                    if (e.is_character()) {
                        char c = e.character()[0];
                        int v = hexval(c);
                        if (v >= 0) {
                            commit_nibble(v);
                            return true;
                        }
                    }
                    // Mouse click while editing
                    const auto& m = e.mouse();
                    if (m.button == ftxui::Mouse::Left && m.motion == ftxui::Mouse::Pressed) {
                        return handleMouseTakeover(m, e);
                    }
                    return false;
                }

                // Navigation keys (not editing)
                if (e == Event::ArrowUp)
                {
                    top_row_ = std::max(0, top_row_ - 1);
                    return true;
                }
                if (e == Event::ArrowDown)
                {
                    top_row_ = std::min(max_top, top_row_ + 1);
                    return true;
                }
                if (e == Event::PageUp)
                {
                    top_row_ = std::max(0, top_row_ - rows_);
                    return true;
                }
                if (e == Event::PageDown)
                {
                    top_row_ = std::min(max_top, top_row_ + rows_);
                    return true;
                }
                if (e == Event::Home)
                {
                    top_row_ = 0;
                    return true;
                }
                if (e == Event::End)
                {
                    top_row_ = max_top;
                    return true;
                }
                if (e == Event::Backspace) {
                    if (!hexEditHistory.empty() && data_ && !data_->empty()) {
                        HexEditHistory lastEdit = hexEditHistory.back();
                        size_t idx = lastEdit.row * bpr_ + lastEdit.col;
                        if (idx < data_->size()) {
                            data_->at(idx) = lastEdit.data;
                            selectedRow = lastEdit.row;
                            selectedColumn = lastEdit.col;
                        }
                        hexEditHistory.pop_back();
                    }
                    markMemoryDirty();
                    return true;
                }

                // If event is not a mouse, just return false
                if (!e.is_mouse()) return false;

                const auto& m = e.mouse();

                // Hover-to-focus: take focus when mouse enters this component
                if (mouseBox.Contain(m.x, m.y) && !Focused()) {
                    TakeFocus();
                }

                // Scroll wheel support (only when mouse is over this component)
                if (mouseBox.Contain(m.x, m.y)) {
                    if (m.button == ftxui::Mouse::WheelUp) {
                        top_row_ = std::max(0, top_row_ - 3);
                        return true;
                    }
                    if (m.button == ftxui::Mouse::WheelDown) {
                        top_row_ = std::min(max_top, top_row_ + 3);
                        return true;
                    }
                }

                if (m.button == ftxui::Mouse::Left && m.motion == ftxui::Mouse::Pressed) {
                    // Let children (e.g., the Autopatch checkbox) handle clicks first.
                    if (ComponentBase::OnEvent(e))
                        return true;

                    // Only enter edit mode when clicking within the byte grid area
                    // (header + visible rows). Ignore footer/separator/checkbox clicks.
                    const int local_y = m.y - mouseBox.y_min - highestY;
                    const int grid_height = 1 /*header*/ + rows_;
                    if (local_y >= 0 && local_y < grid_height)
                        return handleMouseTakeover(m, e);

                    return false;
                }

                return ComponentBase::OnEvent(e);
            }

            /*====================================*/
            /*====================================*/

            Element OnRender() override
            {
                // Check if a specific register is being tracked
                if (!followedReg_.empty())
                {
                    // If the value doesn't equal the current base address
                    uint64_t regValue = getRegisterValue(followedReg_);
                    if (regValue != base_addr_)
                    {
                        base_addr_ = regValue;
                        top_row_ = 0;
                    }
                }

                data_ = Emulator::getMemory(base_addr_, size_, -1, cache_key_);

                std::vector<Element> lines;
                lines.reserve(rows_ + 2);

                auto header = hbox({text(" Address             "), text("Bytes") | bold}) | underlined | dim;
                lines.push_back(header);

                // Use actual data size, not requested size, to avoid out-of-bounds access
                const size_t actual_size = (data_ != nullptr) ? data_->size() : 0;
                const int max_rows = static_cast<int>((actual_size + bpr_ - 1) / bpr_);
                const int end_row = std::min(top_row_ + rows_, max_rows);

                for (int r = top_row_; r < end_row && data_ != nullptr && !data_->empty(); ++r)
                {
                    size_t start = static_cast<size_t>(r) * bpr_;

                    // Write the address for currently selected address space
                    auto addr_el = text(hex8ByteStr(base_addr_ + start)) | color(Color::CornflowerBlue);

                    std::vector<Element> byte_els;
                    byte_els.reserve(bpr_ * 2 - 1);
                    for (int i = 0; i < bpr_; ++i)
                    {
                        size_t idx = start + i;
                        if (idx < actual_size)
                        {
                            // Show the data bytes
                            uint8_t b = data_->at(idx);
                            Element e = text(hex1ByteStr(b)) | color(Color::Magenta);

                            // Dim NULL bytes for readability
                            if (b == 0x00)
                                e = e | dim;

                            // Handle highlighting for edited bytes
                            bool isHighlighted = std::find(editTrail.begin(), editTrail.end(),
                               std::make_pair(r,i)) != editTrail.end();
                            if (isHighlighted) {
                                e = e | bgcolor(Color::Black) | bold;
                            }

                            byte_els.push_back(e);
                        }
                        else
                        {
                            byte_els.push_back(text("  ") | dim);
                        }
                        if (i + 1 != bpr_)
                            byte_els.push_back(text(" "));
                    }

                    // Add the lines to the box that will be displayed.
                    lines.push_back(hbox({addr_el, text(": "), hbox(std::move(byte_els))}));
                }

                // Show what we're currently tracking
                std::string trackingInfo;
                if (!followedReg_.empty()) {
                    trackingInfo = "Tracking: " + followedReg_ + " (/ or Ctrl+F to change)";
                } else {
                    trackingInfo = "Address: " + hex8ByteStr(base_addr_) + " (/ or Ctrl+F to change)";
                }

                // Final display
                Element display;

                if (gotoMode_) {
                    // Show goto input bar - no bgcolor for transparent background
                    auto gotoBar = hbox({
                        text("Goto: ") | bold | color(Color::Magenta),
                        text(gotoInput_) | color(Color::Magenta),
                        text("_") | blink | color(Color::Magenta),
                    });

                    display = vbox({
                        vbox(std::move(lines)),
                        separator(),
                        gotoBar,
                        shouldAutopatch->Render(),
                    }) | border | focus;
                } else {
                    display = vbox({
                        vbox(std::move(lines)),
                        separator(),
                        text(trackingInfo) | dim,
                        shouldAutopatch->Render(),
                    }) | border | focus;
                }

                if (Focused())
                    return display | color(Color::Magenta) | reflect(mouseBox);

                return vbox({display | reflect(mouseBox)});
            }
        };

        // IMPORTANT: pass the args to Impl here
        return Make<Impl>(state, std::move(followedReg), size, base_addr, bytesPerRow, visibleRows);
    }

}
