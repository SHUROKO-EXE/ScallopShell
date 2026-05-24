#pragma once

#include "appstate.hpp"
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <string>

namespace ScallopUI {

ftxui::Component AssemblerDisplay(AppStatePtr appState, const std::string& arch);

}
