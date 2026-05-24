#include "registerdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

namespace ScallopUI
{

    Component RegisterDisplay(AppStatePtr appStatePtr)
    {
        class Impl : public ComponentBase
        {
        private:

            int rows;
            int currentTopRow = 0;
            int min_top = 37;
            int instructionCount = 0;
            int maxTopRow = 0;
            Box renderedArea;
            bool follow_tail = false;
            int totalLines = 0;
            int lastTotalLines = 0;
            AppStatePtr state;

            bool Focusable() const override { return true; }

            bool OnEvent(Event e) override {

                if (e == Event::ArrowUp) {
                    if (currentTopRow > 0) currentTopRow--;
                    follow_tail = false;
                    return true;
                }

                if (e == Event::ArrowDown) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    if (currentTopRow < maxTopRow) currentTopRow++;
                    if (currentTopRow >= maxTopRow) follow_tail = true;
                    return true;
                }

                if (e == Event::PageUp) {
                    currentTopRow = std::max(0, currentTopRow - min_top);
                    follow_tail = false;
                    return true;
                }

                if (e == Event::PageDown) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    currentTopRow = std::min(maxTopRow, currentTopRow + min_top);
                    if (currentTopRow >= maxTopRow) follow_tail = true;
                    return true;
                }

                if (e.is_mouse()) {

                    state->toggleRightMenuSize(0);

                    const auto& m = e.mouse();
                    if (!renderedArea.Contain(m.x, m.y))
                        return false;

                    if (Focused() && m.button == Mouse::WheelUp) {
                        if (currentTopRow > 0) currentTopRow--;
                        follow_tail = false;
                        return true;
                    }
                    if (Focused() && m.button == Mouse::WheelDown) {
                        int maxTopRow = std::max(0, totalLines - min_top);
                        if (currentTopRow < maxTopRow) currentTopRow++;
                        if (currentTopRow >= maxTopRow) follow_tail = true;
                        return true;
                    }
                    return false;
                }

                return ComponentBase::OnEvent(e);

            }


            Element OnRender() override
            {

                const std::vector<std::string> *registers = Emulator::getRegisters();

                std::vector<Element> allLines;
                auto headerColor = Color::CornflowerBlue;

                auto header = hbox({text("  Register View")}) | underlined | dim | bold | color(headerColor);
                allLines.push_back(header);
                allLines.push_back(text("--------------------------------------------------------------------------------------------------------------------------------"));

                for (uint r = 0; r < registers->size(); r++)
                {
                    if (r + 1 < registers->size())
                    {
                        Element left;

                        if (r % 2) {
                            left = text(" " + registers->at(r)) | color(Color::Magenta) | size(WIDTH, EQUAL, 50);
                        }
                        else {
                            left = text(registers->at(r)) | color(Color::CornflowerBlue) | size(WIDTH, EQUAL, 50);
                        }

                        allLines.emplace_back(hbox({left}));
                    }
                    else
                    {
                        allLines.emplace_back(text(registers->at(r)) | color(Color::CornflowerBlue));
                    }
                }

                totalLines = static_cast<int>(allLines.size());
                int maxTopRow = std::max(0, totalLines - min_top);

                if (follow_tail)
                    currentTopRow = maxTopRow;

                currentTopRow = std::max(0, std::min(maxTopRow, currentTopRow));

                int start = currentTopRow;
                int end = std::min(totalLines, currentTopRow + min_top);
                std::vector<Element> visibleLines(allLines.begin() + start, allLines.begin() + end);

                auto display = vbox(visibleLines) | border | reflect(renderedArea);

                if (Focused())
                    return display | color(Color::Magenta);
                else
                    return display;
            }

        public:
            Impl(AppStatePtr appStatePtr)
            {
                state = appStatePtr;
            }
        };

        return Make<Impl>(appStatePtr);
    }
}