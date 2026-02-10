#include "cligui.hpp"
#include "emulatorAPI.hpp"
#include <memory>
#include <stdlib.h>

using namespace ftxui;

std::vector<int> lastRunArgs;

enum class LastRunFunction {
    step,
    continueExec,
    dumpMemory,
    focusMemory,
    defocusMemory,
} lastRunFunction;

void exitScallop() {
    auto* screen = ftxui::ScreenInteractive::Active();
    if (screen) {
        screen->Exit();
    }
}

void step(int n = 1)
{
    lastRunFunction = LastRunFunction::step;
    Emulator::step(n);
    lastRunArgs.clear();
    lastRunArgs.emplace_back(n);
}

void breakpoint(uint64_t addr) {
    static std::string random = "";
    Emulator::addBreakpoint(addr, random);
}

void deleteBreakpoint(uint64_t addr) {
    Emulator::deleteBreakpoint(addr);
}

void continueExec()
{
    lastRunFunction = LastRunFunction::continueExec;
    Emulator::continueExec();
    lastRunArgs.clear();
}

void dumpMemory() {
    lastRunFunction = LastRunFunction::dumpMemory;
    lastRunArgs.clear();
}

void focusMemory(uint64_t low, uint64_t high)  {
    lastRunFunction = LastRunFunction::focusMemory;
    Emulator::focusMemory(low, high);
    lastRunArgs.clear();
}

void defocusMemory(uint64_t low, uint64_t high)  {
    lastRunFunction = LastRunFunction::defocusMemory;
    Emulator::defocusMemory(low, high);
    lastRunArgs.clear();
}

void resetEmulator() {
    Emulator::startEmulation("", "");
}

void runLastFunc() {
    switch (lastRunFunction) {
    case LastRunFunction::step:
        step(lastRunArgs.at(0));
        break;
    case LastRunFunction::continueExec:
        continueExec();
        break;
    case LastRunFunction::dumpMemory:
        dumpMemory();
        break;
    case LastRunFunction::focusMemory:
        // We can ignore this to be honest
        break;
    case LastRunFunction::defocusMemory:
        // We can ignore this to be honest
        break;
    }
}

namespace ScallopUI
{

    std::vector<std::string> history;
    uint historyMaxLen = 1;
    CLI::App app("Scallop Shell");
    ftxui::Box mouseBox;

    Component InputCli()
    {
        struct Impl : ComponentBase
        {
        
            std::shared_ptr<std::string> content = std::make_shared<std::string>();
            std::shared_ptr<std::string> placeholder = std::make_shared<std::string>(" > ");

            Component input;

            Impl()
            {
                lastRunFunction = LastRunFunction::step;
                InputOption opt = InputOption::Default();
                opt.password = false;
                opt.placeholder = placeholder.get(); // safe: Impl owns it
                opt.transform = [](InputState s)
                {
                    Element e = std::move(s.element);
                    if (s.is_placeholder)
                        e |= dim;

                    e |= border;
                    /*if (s.focused)
                        e |= border;
                    else if (s.hovered)
                        e |= borderRounded;
                    else
                        e |= borderEmpty;*/
                    return e; // no bgcolor/inverted => transparent
                };

                input = Input(content.get(), opt);

                Add(input);
                
            }

            bool OnEvent(Event e) override {
                // Hover-to-focus and click-to-focus
                if (e.is_mouse() && mouseBox.Contain(e.mouse().x, e.mouse().y)) {
                    if (!Focused()) {
                        TakeFocus();
                    }
                    // Consume clicks but not hovers
                    if (e.mouse().button == Mouse::Left && e.mouse().motion == Mouse::Pressed) {
                        return true;
                    }
                }

                // Let the container handle focus traversal
                if (e == Event::Tab || e == Event::TabReverse)
                    return false;

                // If not focused, don't eat keys
                if (!ComponentBase::Focused())
                    return false;

                // Enter => submit command
                if (e == Event::Return) {
                    const std::string line = *content;
                    if (line.empty()) runLastFunc();
                    else history.emplace_back(line);
                    content->clear();

                    try {
                    app.parse(line);
                    } catch (const CLI::ParseError &pe) {
                    (void)app.exit(pe);  // consume status
                    
                    }
                    app.clear();           // reset CLI parser state

                    return true;
                }

                // Otherwise, let the inner Input handle typing, arrows, backspace, etc.
                if (input->OnEvent(e)) return true;

                // Fallback so other decorators/containers still get a chance
                return ComponentBase::OnEvent(e);
            }

            bool Focusable() const override { return true; }

            Element OnRender() override {
                // Render the child input and reflect its box for click-to-focus
                auto inner = input->Render() | reflect(mouseBox);

                // Always draw a border; highlight when focused
                return inner
                    | border
                    | color(ComponentBase::Focused() ? Color::Magenta : Color::GrayDark);
            }
            
        };

        return Make<Impl>();
    }

    /**
     * History of past user commands.
     */
    Component CliHistory()
    {

        struct Impl : ComponentBase {

            bool Focusable() const override { return false; }

            Element OnRender() override {
                Elements lines;

                if (history.size() > historyMaxLen)
                    history.erase(history.begin());

                for (int i = history.size() - 1; i >= 0; i--)
                    lines.push_back(text(history.at(i)));

                return vbox(std::move(lines)) | border | vscroll_indicator | frame;
            };

        };

        return Make<Impl>();

    }

    void initCliCommands()
    {
        static int n;
        auto stepCmd = app.add_subcommand("step", "Execute N CPU steps");
        stepCmd
            ->add_option("n", n, "Number of steps")
            ->expected(0, 1)                 // allow 0 or 1 positional arguments
            ->default_val("1")
            ->check(CLI::PositiveNumber);    // or CLI::Range(1, 1'000'000)

        stepCmd->callback([&](){

            step(n); // pass the parsed value (or default) into step()
            n = 1;
        });


      
        auto continCmd = app.add_subcommand("continue", "Run program until breakpoint or program exit");
        continCmd->callback(continueExec);


        uint64_t low, high;
        auto focusMem = app.add_subcommand("focus", "Filter out all code outside of this range");
        focusMem
            ->add_option("low", low, "Low addr")
            ->expected(1)                 
            ->check(CLI::PositiveNumber);    // or CLI::Range(1, 1'000'000)
        focusMem
            ->add_option("high", high, "high addr")
            ->expected(1)                 
            ->check(CLI::PositiveNumber);    // or CLI::Range(1, 1'000'000)
        focusMem->callback([&](){
            focusMemory(low, high);
        });

        auto defocusMem = app.add_subcommand("defocus", "Remove a focused range");
        defocusMem
            ->add_option("low", low, "Low addr")
            ->expected(1)
            ->check(CLI::PositiveNumber);
        defocusMem
            ->add_option("high", high, "high addr")
            ->expected(1)
            ->check(CLI::PositiveNumber);
        defocusMem->callback([&](){
            defocusMemory(low, high);
        });

        auto dumpMem = app.add_subcommand("dump", "Dump memory");
        dumpMem->callback(dumpMemory);

        auto reset = app.add_subcommand("reset");
        reset->callback(resetEmulator);

        auto exitCall = app.add_subcommand("exit");
        exitCall->callback(exitScallop);

        std::string breakAddrStr;
        std::string unbreakAddrStr;

        auto breakAt = app.add_subcommand("break", "Add a breakpoint");
        breakAt->add_option("addr", breakAddrStr, "Address (decimal or 0x...)")
            ->required();

        breakAt->callback([&](){

            //std::cerr << "breakAddr currently = " << breakAddrStr << "\n";
           
            uint64_t addr = 0;
            try {
                size_t idx = 0;
                int base = 10;

                if (breakAddrStr.size() > 2 && breakAddrStr[0] == '0' &&
                (breakAddrStr[1] == 'x' || breakAddrStr[1] == 'X')) {
                    base = 16;
                }

                addr = std::stoull(breakAddrStr, &idx, base);

                // reject trailing junk like "0x123abcZZ"
                if (idx != breakAddrStr.size())
                    throw std::invalid_argument("trailing characters");

            } catch (...) {
                throw CLI::ValidationError("addr", "Invalid address: " + breakAddrStr);
            }
            
            //std::cerr << "breakAddr currently = " << addr << "\n";
           
            breakpoint(addr);
        });
        // 0x7f4d0c6be3d4

        auto unbreakAt = app.add_subcommand("unbreak", "Remove a breakpoint");
        unbreakAt->add_option("addr", unbreakAddrStr, "Address (decimal or 0x...)")
            ->required();

        unbreakAt->callback([&](){

            uint64_t addr = 0;
            try {
                size_t idx = 0;
                int base = 10;

                if (unbreakAddrStr.size() > 2 && unbreakAddrStr[0] == '0' &&
                (unbreakAddrStr[1] == 'x' || unbreakAddrStr[1] == 'X')) {
                    base = 16;
                }

                addr = std::stoull(unbreakAddrStr, &idx, base);

                // reject trailing junk like "0x123abcZZ"
                if (idx != unbreakAddrStr.size())
                    throw std::invalid_argument("trailing characters");

            } catch (...) {
                throw CLI::ValidationError("addr", "Invalid address: " + unbreakAddrStr);
            }

            std::cerr << "unbreakAddr currently = " << addr << "\n";

            std::cerr << "sending unbreak for addr = " << unbreakAddrStr << "\n";
            deleteBreakpoint(addr);
        });
    }

} // namespace ScallopUI
