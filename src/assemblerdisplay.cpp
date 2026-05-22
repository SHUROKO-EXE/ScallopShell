#include "assemblerdisplay.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#ifdef SCALLOP_HAS_KEYSTONE
#include <keystone/keystone.h>
#endif

using namespace ftxui;

namespace ScallopUI {
namespace {

std::string formatBytes(const unsigned char* data, size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        if (i != 0)
            out << ' ';
        out << std::setw(2) << static_cast<int>(data[i]);
    }
    return out.str();
}

} // namespace

Component AssemblerDisplay() {
    struct Impl : ComponentBase {
        std::vector<std::string> syntaxNames_ = {"intel", "at&t"};
        std::string assembly_ = "nop";
        std::string bytes_;
        std::string status_;
        int syntax_ = 0;
        int activeChild_ = 1;
        Component syntaxToggle_;
        Component input_;
        Component container_;
        Box renderBox_;

        Impl() {
            MenuOption syntaxOption = MenuOption::Toggle();
            syntaxOption.on_change = [this] { assemble(); };
            syntaxToggle_ = Menu(&syntaxNames_, &syntax_, syntaxOption);

            InputOption inputOption = InputOption::Default();
            inputOption.placeholder = "x86-64 assembly";
            inputOption.multiline = true;
            inputOption.on_change = [this] { assemble(); };
            inputOption.transform = [](InputState state) {
                Element element = std::move(state.element);
                if (state.is_placeholder)
                    element |= dim;
                return element;
            };
            input_ = Input(&assembly_, inputOption);

            container_ = Container::Vertical({syntaxToggle_, input_}, &activeChild_);
            Add(container_);
            assemble();
        }

        bool Focusable() const override { return true; }

        bool OnEvent(Event event) override {
            if (event.is_mouse()) {
                const auto& mouse = event.mouse();
                if (renderBox_.Contain(mouse.x, mouse.y) && !Focused())
                    TakeFocus();
            }

            return container_->OnEvent(event);
        }

        Element OnRender() override {
            auto status = text(status_) | dim;
#ifndef SCALLOP_HAS_KEYSTONE
            status = text(status_) | color(Color::Red1);
#endif

            auto inputBox = vbox({
                hbox({
                    text(" Assembly") | bold | dim | color(Color::CornflowerBlue),
                    filler(),
                    text("Syntax: ") | dim,
                    syntaxToggle_->Render(),
                }),
                separator(),
                input_->Render() | flex,
            }) | border | flex;

            auto output = bytes_.empty() ? text("(no bytes)") | dim
                                         : paragraph(bytes_) | color(Color::Magenta);

            auto outputBox = vbox({
                text(" Bytes") | bold | dim | color(Color::CornflowerBlue),
                separator(),
                output | flex,
            }) | border | size(HEIGHT, GREATER_THAN, 4);

            auto display = vbox({
                hbox({
                    text(" Assembler") | bold | dim,
                    filler(),
                    status,
                }),
                separator(),
                inputBox,
                outputBox,
            }) | borderStyled(Focused() ? Color::Magenta : Color::GrayDark)
               | reflect(renderBox_);

            return display;
        }

        void assemble() {
#ifndef SCALLOP_HAS_KEYSTONE
            bytes_.clear();
            status_ = "Keystone assembler backend unavailable";
#else
            ks_engine* engine = nullptr;
            ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &engine);
            if (err != KS_ERR_OK) {
                bytes_.clear();
                status_ = ks_strerror(err);
                return;
            }

            const int syntax = syntax_ == 0 ? KS_OPT_SYNTAX_INTEL
                                            : KS_OPT_SYNTAX_ATT;
            err = ks_option(engine, KS_OPT_SYNTAX, syntax);
            if (err != KS_ERR_OK) {
                bytes_.clear();
                status_ = ks_strerror(err);
                ks_close(engine);
                return;
            }

            unsigned char* encoded = nullptr;
            size_t size = 0;
            size_t count = 0;
            if (ks_asm(engine, assembly_.c_str(), 0, &encoded, &size, &count) != KS_ERR_OK) {
                bytes_.clear();
                status_ = ks_strerror(ks_errno(engine));
                ks_close(engine);
                return;
            }

            bytes_ = formatBytes(encoded, size);
            status_ = std::to_string(count) + " instruction(s), " +
                      std::to_string(size) + " byte(s)";
            ks_free(encoded);
            ks_close(engine);
#endif
        }
    };

    return Make<Impl>();
}

} // namespace ScallopUI
