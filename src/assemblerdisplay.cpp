#include "assemblerdisplay.hpp"
#include "appstate.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifdef SCALLOP_HAS_KEYSTONE
#include <keystone/keystone.h>
#endif

using namespace ftxui;

namespace ScallopUI {
namespace {

struct ToggleChoice {
    std::string label;
    int value = 0;
};

struct ArchProfile {
    std::string qemuArch;
    std::string displayArch;
    std::string placeholder;
    std::vector<ToggleChoice> syntaxChoices;
    std::vector<ToggleChoice> endianChoices;
    int defaultEndian = 0;
    bool supported = false;

#ifdef SCALLOP_HAS_KEYSTONE
    ks_arch keystoneArch = KS_ARCH_X86;
    int baseMode = KS_MODE_64;
#endif
};

std::string normalizeArch(std::string arch) {
    std::transform(arch.begin(), arch.end(), arch.begin(), [](unsigned char c) {
        if (c == '-')
            return '_';
        return static_cast<char>(std::tolower(c));
    });
    return arch;
}

bool startsWith(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool endsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool contains(const std::string& value, const std::string& needle) {
    return value.find(needle) != std::string::npos;
}

std::vector<std::string> labelsFrom(const std::vector<ToggleChoice>& choices) {
    std::vector<std::string> labels;
    labels.reserve(choices.size());
    for (const auto& choice : choices)
        labels.push_back(choice.label);
    return labels;
}

int bigEndianMode() {
#ifdef SCALLOP_HAS_KEYSTONE
    return KS_MODE_BIG_ENDIAN;
#else
    return 0;
#endif
}

void setEndianChoices(ArchProfile& profile, bool canChoose, bool defaultBig) {
    profile.endianChoices.clear();
    if (canChoose) {
        profile.endianChoices.push_back({"little", 0});
        profile.endianChoices.push_back({"big", bigEndianMode()});
        profile.defaultEndian = defaultBig ? 1 : 0;
        return;
    }

    profile.endianChoices.push_back({
        defaultBig ? "big" : "little",
        defaultBig ? bigEndianMode() : 0,
    });
    profile.defaultEndian = 0;
}

void setDefaultSyntax(ArchProfile& profile) {
    profile.syntaxChoices = {{"default", 0}};
}

void setX86Syntax(ArchProfile& profile) {
#ifdef SCALLOP_HAS_KEYSTONE
    profile.syntaxChoices = {
        {"intel", KS_OPT_SYNTAX_INTEL},
        {"at&t", KS_OPT_SYNTAX_ATT},
    };
#else
    profile.syntaxChoices = {{"intel", 0}, {"at&t", 0}};
#endif
}

void markUnsupported(ArchProfile& profile, const std::string& arch) {
    profile.supported = false;
    profile.displayArch = arch.empty() ? "unknown" : arch;
    profile.placeholder = profile.displayArch + " assembly";
    setDefaultSyntax(profile);
    setEndianChoices(profile, false, false);
}

ArchProfile profileForArch(const std::string& rawArch) {
    const std::string arch = normalizeArch(rawArch);
    ArchProfile profile;
    profile.qemuArch = rawArch;
    profile.displayArch = arch.empty() ? "unknown" : arch;
    profile.placeholder = profile.displayArch + " assembly";
    profile.supported = true;
    setDefaultSyntax(profile);
    setEndianChoices(profile, false, false);

    const auto useX86 = [&](int mode) {
        setX86Syntax(profile);
        setEndianChoices(profile, false, false);
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_X86;
        profile.baseMode = mode;
#else
        (void)mode;
#endif
    };

    const auto useFixedEndian = [&](bool defaultBig) {
        setDefaultSyntax(profile);
        setEndianChoices(profile, false, defaultBig);
    };

    const auto useSelectableEndian = [&](bool defaultBig) {
        setDefaultSyntax(profile);
        setEndianChoices(profile, true, defaultBig);
    };

    if (arch == "x86_64" || arch == "amd64") {
#ifdef SCALLOP_HAS_KEYSTONE
        useX86(KS_MODE_64);
#else
        useX86(0);
#endif
        return profile;
    }

    if (arch == "x86" ||
        (arch.size() == 4 && arch[0] == 'i' && arch[2] == '8' && arch[3] == '6')) {
#ifdef SCALLOP_HAS_KEYSTONE
        useX86(KS_MODE_32);
#else
        useX86(0);
#endif
        return profile;
    }

    if (arch == "aarch64" || arch == "aarch64_be" || arch == "arm64" || arch == "arm64_be") {
        useSelectableEndian(endsWith(arch, "_be"));
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_ARM64;
        profile.baseMode = 0;
#endif
        return profile;
    }

    if (startsWith(arch, "arm") && !startsWith(arch, "arm64")) {
        useSelectableEndian(contains(arch, "eb") || endsWith(arch, "_be"));
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_ARM;
        profile.baseMode = KS_MODE_ARM;
#endif
        return profile;
    }

    if (startsWith(arch, "mips")) {
        const bool isLittle = endsWith(arch, "el") || contains(arch, "el_");
        useSelectableEndian(!isLittle);
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_MIPS;
        profile.baseMode = contains(arch, "64") ? KS_MODE_MIPS64 : KS_MODE_MIPS32;
#endif
        return profile;
    }

    if (startsWith(arch, "ppc") || startsWith(arch, "powerpc")) {
        useSelectableEndian(!endsWith(arch, "le"));
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_PPC;
        profile.baseMode = contains(arch, "64") ? KS_MODE_PPC64 : KS_MODE_PPC32;
#endif
        return profile;
    }

    if (startsWith(arch, "sparc")) {
        useFixedEndian(true);
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_SPARC;
        profile.baseMode = contains(arch, "64") ? (KS_MODE_SPARC64 | KS_MODE_V9)
                                                : KS_MODE_SPARC32;
#endif
        return profile;
    }

    if (arch == "s390x" || arch == "systemz") {
        useFixedEndian(true);
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_SYSTEMZ;
        profile.baseMode = 0;
#endif
        return profile;
    }

    if (arch == "hexagon") {
        useFixedEndian(false);
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_HEXAGON;
        profile.baseMode = 0;
#endif
        return profile;
    }

    if (arch == "evm") {
        useFixedEndian(false);
#ifdef SCALLOP_HAS_KEYSTONE
        profile.keystoneArch = KS_ARCH_EVM;
        profile.baseMode = 0;
#endif
        return profile;
    }

    markUnsupported(profile, arch);
    return profile;
}

#ifdef SCALLOP_HAS_KEYSTONE
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

ArchProfile makeProfile(const std::string& label) {
    ArchProfile profile;
    profile.qemuArch = label;
    profile.displayArch = label;
    profile.placeholder = label + " assembly";
    profile.supported = true;
    setDefaultSyntax(profile);
    setEndianChoices(profile, false, false);
    return profile;
}

ArchProfile makeKeystoneProfile(const std::string& label, ks_arch arch, int mode) {
    ArchProfile profile = makeProfile(label);
    profile.keystoneArch = arch;
    profile.baseMode = mode;
    return profile;
}

bool canOpenTarget(const ArchProfile& profile, int endianMode) {
    if (!profile.supported || !ks_arch_supported(profile.keystoneArch))
        return false;

    ks_engine* engine = nullptr;
    const ks_err err = ks_open(profile.keystoneArch, profile.baseMode | endianMode, &engine);
    if (err == KS_ERR_OK)
        ks_close(engine);
    return err == KS_ERR_OK;
}

void filterUnavailableEndianChoices(ArchProfile& profile) {
    const int preferredEndian =
        profile.endianChoices.empty() ? 0
                                      : profile.endianChoices[static_cast<size_t>(profile.defaultEndian)].value;

    std::vector<ToggleChoice> available;
    for (const auto& choice : profile.endianChoices) {
        if (canOpenTarget(profile, choice.value))
            available.push_back(choice);
    }

    profile.endianChoices = std::move(available);
    profile.defaultEndian = 0;
    for (size_t i = 0; i < profile.endianChoices.size(); ++i) {
        if (profile.endianChoices[i].value == preferredEndian) {
            profile.defaultEndian = static_cast<int>(i);
            break;
        }
    }
    profile.supported = !profile.endianChoices.empty();
}
#endif

std::vector<ArchProfile> availableTargetProfiles(const ArchProfile& detectedProfile) {
    std::vector<ArchProfile> profiles;

#ifdef SCALLOP_HAS_KEYSTONE
    const auto add = [&](ArchProfile profile) {
        filterUnavailableEndianChoices(profile);
        if (profile.supported)
            profiles.push_back(std::move(profile));
    };

    const auto addX86 = [&](const std::string& label, int mode) {
        ArchProfile profile = makeKeystoneProfile(label, KS_ARCH_X86, mode);
        setX86Syntax(profile);
        setEndianChoices(profile, false, false);
        add(std::move(profile));
    };

    const auto addSelectableEndian = [&](const std::string& label, ks_arch arch, int mode) {
        ArchProfile profile = makeKeystoneProfile(label, arch, mode);
        setDefaultSyntax(profile);
        setEndianChoices(profile, true, false);
        add(std::move(profile));
    };

    const auto addFixedEndian = [&](const std::string& label, ks_arch arch, int mode, bool bigEndian) {
        ArchProfile profile = makeKeystoneProfile(label, arch, mode);
        setDefaultSyntax(profile);
        setEndianChoices(profile, false, bigEndian);
        add(std::move(profile));
    };

    addX86("x86-16", KS_MODE_16);
    addX86("x86-32", KS_MODE_32);
    addX86("x86-64", KS_MODE_64);
    addSelectableEndian("arm", KS_ARCH_ARM, KS_MODE_ARM);
    addSelectableEndian("thumb", KS_ARCH_ARM, KS_MODE_THUMB);
    addSelectableEndian("arm64", KS_ARCH_ARM64, 0);
    addSelectableEndian("mips32", KS_ARCH_MIPS, KS_MODE_MIPS32);
    addSelectableEndian("mips64", KS_ARCH_MIPS, KS_MODE_MIPS64);
    addSelectableEndian("ppc32", KS_ARCH_PPC, KS_MODE_PPC32);
    addSelectableEndian("ppc64", KS_ARCH_PPC, KS_MODE_PPC64);
    addFixedEndian("sparc32", KS_ARCH_SPARC, KS_MODE_SPARC32, true);
    addFixedEndian("sparc64", KS_ARCH_SPARC, KS_MODE_SPARC64 | KS_MODE_V9, true);
    addFixedEndian("systemz", KS_ARCH_SYSTEMZ, 0, true);
    addFixedEndian("hexagon", KS_ARCH_HEXAGON, 0, false);
    addFixedEndian("evm", KS_ARCH_EVM, 0, false);
#else
    profiles.push_back(detectedProfile);
#endif

    if (profiles.empty())
        profiles.push_back(detectedProfile);
    return profiles;
}

std::vector<std::string> targetLabelsFrom(const std::vector<ArchProfile>& profiles) {
    std::vector<std::string> labels;
    labels.reserve(profiles.size());
    for (const auto& profile : profiles)
        labels.push_back(profile.displayArch);
    return labels;
}

bool sameBackendTarget(const ArchProfile& lhs, const ArchProfile& rhs) {
#ifdef SCALLOP_HAS_KEYSTONE
    return lhs.supported && rhs.supported &&
           lhs.keystoneArch == rhs.keystoneArch &&
           lhs.baseMode == rhs.baseMode;
#else
    return lhs.displayArch == rhs.displayArch;
#endif
}

int targetIndexForDetectedProfile(const std::vector<ArchProfile>& profiles,
                                  const ArchProfile& detectedProfile) {
    for (size_t i = 0; i < profiles.size(); ++i) {
        if (sameBackendTarget(profiles[i], detectedProfile))
            return static_cast<int>(i);
    }
    return 0;
}

int choiceIndexForValue(const std::vector<ToggleChoice>& choices, int value, int fallback) {
    for (size_t i = 0; i < choices.size(); ++i) {
        if (choices[i].value == value)
            return static_cast<int>(i);
    }
    return fallback;
}

int defaultEndianForTarget(const ArchProfile& target, const ArchProfile& detectedProfile) {
    if (sameBackendTarget(target, detectedProfile) && !detectedProfile.endianChoices.empty()) {
        const int detectedEndian =
            detectedProfile.endianChoices[static_cast<size_t>(detectedProfile.defaultEndian)].value;
        return choiceIndexForValue(target.endianChoices, detectedEndian, target.defaultEndian);
    }
    return target.defaultEndian;
}

} // namespace

Component AssemblerDisplay(AppStatePtr appState, const std::string& arch) {
    struct Impl : ComponentBase {
        ArchProfile detectedProfile_;
        ArchProfile profile_;
        std::vector<ArchProfile> targets_;
        std::vector<std::string> targetNames_;
        std::vector<std::string> syntaxNames_;
        std::vector<std::string> endianNames_;
        std::string assembly_ = "nop";
        std::string bytes_;
        std::string status_;
        int target_ = 0;
        int syntax_ = 0;
        int endian_ = 0;
        int activeChild_ = 0;
        int inputChild_ = 0;
        Component targetRadiobox_;
        Component syntaxToggle_;
        Component endianToggle_;
        Component input_;
        Component container_;
        Box renderBox_;
        Box inputBox_;
        AppStatePtr appState; 

        explicit Impl(AppStatePtr appStatePtr, std::string targetArch)
            : detectedProfile_(profileForArch(targetArch)), appState(appStatePtr) {
            targets_ = availableTargetProfiles(detectedProfile_);
            targetNames_ = targetLabelsFrom(targets_);
            target_ = targetIndexForDetectedProfile(targets_, detectedProfile_);
            applyTargetSelection(true);

            targetRadiobox_ = Radiobox(&targetNames_, &target_);

            MenuOption syntaxOption = MenuOption::Toggle();
            syntaxOption.on_change = [this] {
                assemble();
                focusInput();
            };
            syntaxToggle_ = Menu(&syntaxNames_, &syntax_, syntaxOption);

            MenuOption endianOption = MenuOption::Toggle();
            endianOption.on_change = [this] {
                assemble();
                focusInput();
            };
            endianToggle_ = Menu(&endianNames_, &endian_, endianOption);

            InputOption inputOption = InputOption::Default();
            inputOption.placeholder = &profile_.placeholder;
            inputOption.multiline = true;
            inputOption.on_change = [this] { assemble(); };
            inputOption.transform = [](InputState state) {
                Element element = std::move(state.element);
                if (state.is_placeholder)
                    element |= dim;
                return element;
            };
            input_ = Input(&assembly_, inputOption);

            rebuildContainer();
            assemble();
        }

        bool Focusable() const override { return true; }

        bool OnEvent(Event event) override {
            if (event.is_mouse()) {
                const auto& mouse = event.mouse();
                if (renderBox_.Contain(mouse.x, mouse.y)) {
                    TakeFocus();
                    if (inputBox_.Contain(mouse.x, mouse.y) || mouse.button == Mouse::None) {
                        focusInput();
                    }
                }

                appState->toggleRightMenuSize(1);
            }

            const int previousTarget = target_;
            const bool handled = container_->OnEvent(event);
            if (target_ != previousTarget) {
                applyTargetSelection(false);
                rebuildContainer();
                assemble();
                focusInput();
                return true;
            }

            if (handled && event.is_mouse()) {
                const auto& mouse = event.mouse();
                if (!inputBox_.Contain(mouse.x, mouse.y))
                    focusInput();
            }
            return handled;
        }

        Element OnRender() override {
            auto status = text(status_) | dim;
#ifndef SCALLOP_HAS_KEYSTONE
            status = text(status_) | color(Color::Red1);
#endif

            auto targetBox = vbox({
                text("Target") | bold | dim | color(Color::CornflowerBlue),
                separator(),
                targetRadiobox_->Render() | vscroll_indicator | frame | size(HEIGHT, LESS_THAN, 7),
            }) | border | size(WIDTH, LESS_THAN, 18);

            auto inputBox = vbox({
                hbox({
                    text(" Assembly (" + profile_.displayArch + ")") | bold | dim | color(Color::CornflowerBlue),
                    filler(),
                    text("Syntax: ") | dim,
                    renderSyntaxControl(),
                    text("  Endian: ") | dim,
                    renderEndianControl(),
                }),
                separator(),
                input_->Render() | flex | reflect(inputBox_),
            }) | border | flex;

            auto editor = hbox({
                targetBox,
                inputBox,
            }) | flex;

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
                editor,
                outputBox,
            }) | borderStyled(Focused() ? Color::Magenta : Color::GrayDark)
               | reflect(renderBox_);

            return display;
        }

        bool hasSelectableSyntax() const {
            return syntaxNames_.size() > 1;
        }

        bool hasSelectableEndian() const {
            return endianNames_.size() > 1;
        }

        void applyTargetSelection(bool useDetectedDefaults) {
            target_ = std::clamp(target_, 0, static_cast<int>(targets_.size()) - 1);
            profile_ = targets_[static_cast<size_t>(target_)];
            syntaxNames_ = labelsFrom(profile_.syntaxChoices);
            endianNames_ = labelsFrom(profile_.endianChoices);
            syntax_ = 0;
            endian_ = useDetectedDefaults ? defaultEndianForTarget(profile_, detectedProfile_)
                                          : profile_.defaultEndian;
            syntax_ = std::clamp(syntax_, 0, static_cast<int>(syntaxNames_.size()) - 1);
            endian_ = std::clamp(endian_, 0, static_cast<int>(endianNames_.size()) - 1);
        }

        void rebuildContainer() {
            Components children;
            children.push_back(targetRadiobox_);
            if (hasSelectableSyntax())
                children.push_back(syntaxToggle_);
            if (hasSelectableEndian())
                children.push_back(endianToggle_);
            inputChild_ = static_cast<int>(children.size());
            activeChild_ = inputChild_;
            children.push_back(input_);

            container_ = Container::Vertical(std::move(children), &activeChild_);
            DetachAllChildren();
            Add(container_);
        }

        void focusInput() {
            activeChild_ = inputChild_;
            if (input_)
                input_->TakeFocus();
        }

        std::string currentSyntaxName() const {
            if (syntaxNames_.empty())
                return "default";
            const int index = std::clamp(syntax_, 0, static_cast<int>(syntaxNames_.size()) - 1);
            return syntaxNames_[static_cast<size_t>(index)];
        }

        std::string currentEndianName() const {
            if (endianNames_.empty())
                return "unknown";
            const int index = std::clamp(endian_, 0, static_cast<int>(endianNames_.size()) - 1);
            return endianNames_[static_cast<size_t>(index)];
        }

        Element renderSyntaxControl() {
            if (hasSelectableSyntax() && syntaxToggle_)
                return syntaxToggle_->Render();
            return text(currentSyntaxName()) | dim;
        }

        Element renderEndianControl() {
            if (hasSelectableEndian() && endianToggle_)
                return endianToggle_->Render();
            return text(currentEndianName() + " (fixed)") | dim;
        }

        void assemble() {
#ifndef SCALLOP_HAS_KEYSTONE
            bytes_.clear();
            status_ = "Keystone assembler backend unavailable";
#else
            if (!profile_.supported) {
                bytes_.clear();
                status_ = "Unsupported architecture: " + profile_.displayArch;
                return;
            }

            if (!ks_arch_supported(profile_.keystoneArch)) {
                bytes_.clear();
                status_ = "Keystone does not support: " + profile_.displayArch;
                return;
            }

            syntax_ = std::clamp(syntax_, 0, static_cast<int>(profile_.syntaxChoices.size()) - 1);
            endian_ = std::clamp(endian_, 0, static_cast<int>(profile_.endianChoices.size()) - 1);

            ks_engine* engine = nullptr;
            const int mode = profile_.baseMode | profile_.endianChoices[static_cast<size_t>(endian_)].value;
            ks_err err = ks_open(profile_.keystoneArch, mode, &engine);
            if (err != KS_ERR_OK) {
                bytes_.clear();
                status_ = ks_strerror(err);
                return;
            }

            const int syntax = profile_.syntaxChoices[static_cast<size_t>(syntax_)].value;
            if (syntax != 0) {
                err = ks_option(engine, KS_OPT_SYNTAX, syntax);
                if (err != KS_ERR_OK) {
                    bytes_.clear();
                    status_ = ks_strerror(err);
                    ks_close(engine);
                    return;
                }
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
            status_ = profile_.displayArch + ": " +
                      std::to_string(count) + " instruction(s), " +
                      std::to_string(size) + " byte(s)";
            ks_free(encoded);
            ks_close(engine);
#endif
        }
    };

    return Make<Impl>(appState, arch);
}

} // namespace ScallopUI
