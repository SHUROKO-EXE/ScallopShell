#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "iostream"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "guihelpers.hpp"
#include "appstate.hpp"

namespace ScallopUI {

    ftxui::Component RegisterDisplay(AppStatePtr appStatePtr);

}