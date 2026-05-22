---
name: edit-scallop-shell-ui
description: Add a new UI element into Scallop Shell or change an existing one
---

# When to use
Use this skill when the user asks to:
- Add a new UI element into the Scallop Shell Debugger's frontend  
- Change an existing UI element in the Scallop Shell Debugger's frontend

# What to do
1. src/main.cpp contains the main() function where the UI elements are initialized. Read it to identify the current existing UI elements. Remember for the rest of this that you are using the FTXUI library for this. You must do your best to prevent any overlapping of code between different UI elements. If it does not NEED to access it as stated by the user, then it should not call that elements functions. 
2. In int main(), ```auto state = std::make_shared<ScallopUI::AppState>();``` initializes the AppState, which contains all touchable UI elements. To add a new selectable UI element, you must add a ftxui::Component with the UI element name to the AppState struct, another enum value in Pane, and then add a case for that enum to the function ftxui::Component getPaneComponent(Pane p). All of these additions / changes need to be made in include/appstate.hpp. 
3. Make new .hpp and .cpp files with the UI element name in lowercase with no spaces, dashes, or underscores, and shorten it to a understandable filename if it will be too long (ex. Dissassembly Display -> disasmdisplay.hpp). 

In the .hpp, you will use #pragma once at the top and define the new UI component in the ScallopUI namespace. You will need to include <ftxui/component/component.hpp>, <ftxui/component/screen_interactive.hpp>, and <ftxui/dom/elements.hpp> in the .hpp. 

Construct the desired UI element: ask the user for specifics whereever necessary. The basic color palette is Color::CornflowerBlue, Color::Magenta, and the default color. The blue and pink are accents. Do not include any other extra colors unless the user explicitly asks you to. 

Remember that you will need to allow selection when the mouse is hovering over the UI element, and if there is no event, you MUST give control back to the AppState. This is to prevent conflict with other elements which require things like keyboard input. An example from the Disassembly Display is given of proper precaution. 

```
// Hover-to-focus
if (e.is_mouse()) {
  const auto& m = e.mouse();
  const bool inRenderedArea = renderedArea.Contain(m.x, m.y);
  const bool inDisasmPaneBySplit = state_ ? (m.x >= state_->disasmSplitSize) : true;
  if (!(inRenderedArea && inDisasmPaneBySplit)) {
    return false;  // Don't steal mouse events from other panes.
  }
  // Only handle explicit checkbox clicks; otherwise let other panes react.
  // Use Released to avoid toggling twice (Pressed + Released).
  if (m.button == Mouse::Left && m.motion == Mouse::Released) {
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
```
4. In main, you have to add the UI element class into the state, like so:
```
state->cliInput = ScallopUI::InputCli();
state->assembler = ScallopUI::AssemblerDisplay(arch);
```
5. If the user has not explicitly stated where the UI element should go, IMMEDIATELY stop and ask where the user wants the element to be, and if inside a Toggle, what location its option should be at. You WILL NOT assume a location. If the user has stated explicitly where they want the UI element in, add it into the constructor of whatever element it is using. Example if they want it in the right tab to the right of the assembler selection:
```
auto right_tab_container = Container::Tab({state->registers, state->assembler}, &state->selectedRightTab);
```
becomes 
```
auto right_tab_container = Container::Tab({state->registers, state->assembler, state->NEW_UI_ELEMENT}, &state->selectedRightTab);
```
6. DO NOT BUILD IT YOURSELF. You will fail to compile. $SCALLOP_SOURCE/build.sh needs to run with root permisions which you cannot have of course. Stop and ask the user to compile this for you and send you the results.
