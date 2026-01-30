#include "iodisplay.hpp"

#include <unistd.h>
#include <fcntl.h>
#include <filesystem>
#include <vector>
#include <string>

using namespace ftxui;

namespace ScallopUI
{

    Component ioDisplay()
    {

        struct Impl : ComponentBase
        {
            std::vector<std::string> lines_;
            std::string currentLine_;
            std::string inputBuffer_;
            std::vector<char> readBuffer_;
            std::string findFDBuffer_;
            Box renderBox_;
            int scrollOffset_ = 0;
            bool followTail_ = true;
            int lastLineCount_ = 0;
            int lastOutputFd_ = -1;
            Component inputComponent_;
            bool findFD = false;
            int watchedFd_ = -1;  // -1 means use default from Emulator

            Impl()
            {
                lines_.push_back("");  // Start with empty line
                readBuffer_.resize(4096);  // Dynamic read buffer

                // Create input component (always available, will check fd dynamically)
                InputOption opt = InputOption::Default();
                opt.placeholder = "Type here, Enter to send...";
                opt.transform = [](InputState s)
                {
                    Element e = std::move(s.element);
                    if (s.is_placeholder)
                        e |= dim;
                    return e;
                };
                inputComponent_ = Input(&inputBuffer_, opt);
                Add(inputComponent_);
            }

            void readFromFd()
            {
                int outputFd = (watchedFd_ >= 0) ? watchedFd_ : Emulator::getOutputFd();
                if (outputFd < 0) return;

                // Detect fd change (e.g., after reset) and clear output
                if (outputFd != lastOutputFd_)
                {
                    lines_.clear();
                    lines_.push_back("");
                    currentLine_.clear();
                    scrollOffset_ = 0;
                    lastLineCount_ = 0;
                    followTail_ = true;
                    lastOutputFd_ = outputFd;
                }

                ssize_t n;

                // Read all available data (non-blocking) using member buffer
                while ((n = ::read(outputFd, readBuffer_.data(), readBuffer_.size() - 1)) > 0)
                {
                    readBuffer_[n] = '\0';

                    // Process each character
                    for (ssize_t i = 0; i < n; i++)
                    {
                        char c = readBuffer_[i];
                        if (c == '\n')
                        {
                            lines_.push_back(currentLine_);
                            currentLine_.clear();
                        }
                        else if (c == '\r')
                        {
                            // Ignore carriage returns
                        }
                        else
                        {
                            currentLine_ += c;
                        }
                    }
                }
            }

            void writeToFd(const std::string& data)
            {
                int inputFd = Emulator::getInputFd();
                if (inputFd < 0) return;

                std::string toWrite = data + "\n";
                ::write(inputFd, toWrite.c_str(), toWrite.size());
            }

            bool Focusable() const override { return true; }

            bool OnEvent(Event e) override
            {
                // Hover-to-focus
                if (e.is_mouse()) {
                    const auto& m = e.mouse();
                    if (renderBox_.Contain(m.x, m.y) && !Focused()) {
                        TakeFocus();
                    }
                }

                if (!Focused()) return false;

                int totalLines = static_cast<int>(lines_.size());
                int maxScroll = std::max(0, totalLines - 1);

                // Ctrl+F or '/' to enter goto mode (when focused and not editing)
                if (Focused() && (e == Event::CtrlF || e == Event::Character('/'))) {
                    findFD = true;
                    findFDBuffer_.clear();
                    return true;
                }

                // Handle goto mode input
                if (findFD) {
                    if (e == Event::Escape) {
                        findFD = false;
                        return true;
                    }
                    if (e == Event::Return) {
                        if (findFDBuffer_.empty()) {
                            // Reset to default
                            if (watchedFd_ >= 0) {
                                ::close(watchedFd_);
                                watchedFd_ = -1;
                            }
                        } else {
                            pid_t pid = Emulator::getChildPid();
                            if (pid > 0) {
                                int targetFd = std::stoi(findFDBuffer_);
                                std::filesystem::path path = std::filesystem::path("/proc") / std::to_string(pid) / "fd" / std::to_string(targetFd);
                                int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK);
                                if (fd >= 0) {
                                    if (watchedFd_ >= 0) ::close(watchedFd_);
                                    watchedFd_ = fd;
                                    // Clear buffer on fd change
                                    lines_.clear();
                                    lines_.push_back("");
                                    currentLine_.clear();
                                    scrollOffset_ = 0;
                                    lastLineCount_ = 0;
                                    followTail_ = true;
                                }
                            }
                        }
                        findFD = false;
                        return true;
                    }
                    if (e == Event::Backspace && !findFDBuffer_.empty()) {
                        findFDBuffer_.pop_back();
                        return true;
                    }
                    if (e.is_character()) {
                        findFDBuffer_ += e.character();
                        return true;
                    }
                    return true; // Consume all events in goto mode
                }

                // Handle scroll keys FIRST, before input component
                if (e == Event::ArrowUp)
                {
                    if (scrollOffset_ > 0) scrollOffset_--;
                    followTail_ = false;
                    return true;
                }
                if (e == Event::ArrowDown)
                {
                    if (scrollOffset_ < maxScroll) scrollOffset_++;
                    if (scrollOffset_ >= maxScroll) followTail_ = true;
                    return true;
                }
                if (Focused() && e.mouse().button == ftxui::Mouse::WheelUp) {
                    if (scrollOffset_ > 0) scrollOffset_--;
                    followTail_ = false;
                    return true;
                }
                if (Focused() && e.mouse().button == ftxui::Mouse::WheelDown) {
                    if (scrollOffset_ < maxScroll) scrollOffset_++;
                    if (scrollOffset_ >= maxScroll) followTail_ = true;
                    return true;
                }
                if (e == Event::PageUp)
                {
                    scrollOffset_ = std::max(0, scrollOffset_ - 10);
                    followTail_ = false;
                    return true;
                }
                if (e == Event::PageDown)
                {
                    scrollOffset_ = std::min(maxScroll, scrollOffset_ + 10);
                    if (scrollOffset_ >= maxScroll) followTail_ = true;
                    return true;
                }
                if (e == Event::Home)
                {
                    scrollOffset_ = 0;
                    followTail_ = false;
                    return true;
                }
                if (e == Event::End)
                {
                    scrollOffset_ = maxScroll;
                    followTail_ = true;
                    return true;
                }
                if (e == Event::Character('g'))
                {
                    scrollOffset_ = maxScroll;
                    followTail_ = true;
                    return true;
                }

                // Handle Enter to send input
                int inputFd = Emulator::getInputFd();
                if (inputFd >= 0 && e == Event::Return && !inputBuffer_.empty())
                {
                    writeToFd(inputBuffer_);
                    inputBuffer_.clear();
                    return true;
                }

                // Let input component handle remaining events (typing, etc.)
                if (inputComponent_ && inputComponent_->OnEvent(e))
                {
                    return true;
                }

                return false;
            }

            Element OnRender() override
            {
                // Read any new data from fd
                readFromFd();

                Elements displayLines;

                // Build all lines including current incomplete line
                std::vector<std::string> allLines = lines_;
                if (!currentLine_.empty())
                {
                    allLines.push_back(currentLine_);
                }

                int totalLines = static_cast<int>(allLines.size());
                int maxScroll = std::max(0, totalLines - 1);

                // Auto-scroll if following tail and new lines arrived
                if (followTail_ || totalLines > lastLineCount_)
                {
                    if (followTail_)
                    {
                        scrollOffset_ = maxScroll;
                    }
                }
                lastLineCount_ = totalLines;

                // Clamp scroll offset
                scrollOffset_ = std::clamp(scrollOffset_, 0, maxScroll);

                // Display lines from scroll offset
                for (size_t i = scrollOffset_; i < allLines.size(); i++)
                {
                    displayLines.push_back(text(allLines[i]));
                }

                if (displayLines.empty())
                {
                    displayLines.push_back(text("(no output)") | dim);
                }

                auto outputContent = vbox(std::move(displayLines)) | vscroll_indicator | frame | flex;

                Elements mainContent;
                mainContent.push_back(text(" I/O") | bold | dim);
                mainContent.push_back(separator());
                mainContent.push_back(outputContent);

                // Add input field if available
                if (inputComponent_)
                {
                    mainContent.push_back(separator());
                    mainContent.push_back(hbox({
                        text("> ") | dim,
                        inputComponent_->Render() | flex,
                    }));
                }

                auto display = vbox(std::move(mainContent));


                auto gotoBar = hbox({
                    text("   Watch FD: ") | bold | color(Color::Magenta),
                    text(findFDBuffer_) | color(Color::Magenta),
                    text("_") | blink | color(Color::Magenta),
                    });

                if (findFD) {
                    display = vbox({display | border | reflect(renderBox_), gotoBar}) ;
                }
                else {
                    display = display | border | reflect(renderBox_);
                }

                if (Focused())
                    return display | color(Color::Magenta);

                return display;
            }
        };

        return Make<Impl>();
    }
}
