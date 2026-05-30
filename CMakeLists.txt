cmake_minimum_required(VERSION 3.15)
project(scallop LANGUAGES CXX)

# top-level CMakeLists.txt
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Debug if not set by caller
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# --- FTXUI ---
include(FetchContent)

# --- FTXUI ---
set(FTXUI_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/ftxui-src")

if (NOT EXISTS "${FTXUI_SOURCE_DIR}/CMakeLists.txt")
  message(STATUS "FTXUI not found — downloading...")
  FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG        v6.1.9
  )
  FetchContent_MakeAvailable(ftxui)
else()
  message(STATUS "Using cached FTXUI in ${FTXUI_SOURCE_DIR}")
  add_subdirectory(${FTXUI_SOURCE_DIR} ${CMAKE_BINARY_DIR}/_deps/ftxui-build EXCLUDE_FROM_ALL)
endif()

set(MIN_SOCKET_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/min_sock-src")
if (NOT EXISTS "${MIN_SOCKET_SOURCE_DIR}/CMakeLists.txt")
  include(FetchContent)
  set(BUILD_MinimalCppSocket_SAMPLES OFF CACHE BOOL "" FORCE) # you don't want the samples in this case
  FetchContent_Declare(
  min_sock
  GIT_REPOSITORY https://github.com/andreacasalino/Minimal-Socket
  GIT_TAG        master
)
FetchContent_MakeAvailable(min_sock)
else()
  message(STATUS "Using cached Minimal Socket Lib in ${MIN_SOCKET_SOURCE_DIR}")
  add_subdirectory(${MIN_SOCKET_SOURCE_DIR} ${CMAKE_BINARY_DIR}/_deps/min_sock-build EXCLUDE_FROM_ALL)
endif()

# --- Keystone ---
option(SCALLOP_ENABLE_KEYSTONE "Enable Keystone assembler backend when available" ON)
option(SCALLOP_FETCH_KEYSTONE "Fetch and build vendored Keystone when no system install is found" OFF)

set(SCALLOP_HAS_KEYSTONE OFF)
set(SCALLOP_KEYSTONE_TARGET "")

if (SCALLOP_ENABLE_KEYSTONE)
  find_path(SCALLOP_KEYSTONE_INCLUDE_DIR NAMES keystone/keystone.h)
  find_library(SCALLOP_KEYSTONE_LIBRARY NAMES keystone)

  if (SCALLOP_KEYSTONE_INCLUDE_DIR AND SCALLOP_KEYSTONE_LIBRARY)
    add_library(scallop_keystone UNKNOWN IMPORTED)
    set_target_properties(scallop_keystone PROPERTIES
      IMPORTED_LOCATION "${SCALLOP_KEYSTONE_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${SCALLOP_KEYSTONE_INCLUDE_DIR}"
    )
    set(SCALLOP_KEYSTONE_TARGET scallop_keystone)
    set(SCALLOP_HAS_KEYSTONE ON)
    message(STATUS "Using system Keystone: ${SCALLOP_KEYSTONE_LIBRARY}")
  elseif (SCALLOP_FETCH_KEYSTONE)
    set(KEYSTONE_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/keystone-src")
    set(BUILD_LIBS_ONLY ON CACHE BOOL "Only build the Keystone library" FORCE)
    set(KEYSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "Do not force static runtime when embedding Keystone" FORCE)

    if (NOT EXISTS "${KEYSTONE_SOURCE_DIR}/CMakeLists.txt")
      message(STATUS "Keystone not found — downloading...")
      FetchContent_Declare(
        keystone
        GIT_REPOSITORY https://github.com/keystone-engine/keystone.git
        GIT_TAG        0.9.2
      )
      FetchContent_MakeAvailable(keystone)
      set(SCALLOP_KEYSTONE_INCLUDE_DIR "${keystone_SOURCE_DIR}/include")
    else()
      message(STATUS "Using cached Keystone in ${KEYSTONE_SOURCE_DIR}")
      add_subdirectory(${KEYSTONE_SOURCE_DIR} ${CMAKE_BINARY_DIR}/_deps/keystone-build EXCLUDE_FROM_ALL)
      set(SCALLOP_KEYSTONE_INCLUDE_DIR "${KEYSTONE_SOURCE_DIR}/include")
    endif()

    if (TARGET keystone)
      set(SCALLOP_KEYSTONE_TARGET keystone)
      set(SCALLOP_HAS_KEYSTONE ON)
    else()
      message(WARNING "Keystone target was not created; assembler backend disabled")
    endif()
  else()
    message(STATUS "Keystone not found; assembler backend disabled")
  endif()
else()
  message(STATUS "Keystone assembler backend disabled")
endif()

# --- Sources ---
# Pull in everything under src/
file(GLOB_RECURSE SCALLOP_SOURCES
     CONFIGURE_DEPENDS
     "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(scallop ${SCALLOP_SOURCES})

# --- Includes ---
target_include_directories(scallop PRIVATE
  ${CMAKE_SOURCE_DIR}/include

)

# --- Capstone ---
find_library(CAPSTONE_LIB capstone REQUIRED)

# --- Threads (FTXUI uses std::thread; link pthread on Linux) ---
find_package(Threads REQUIRED)

# --- Link ---
target_link_libraries(scallop PRIVATE
  ftxui::component
  ftxui::dom
  ftxui::screen
  ${CAPSTONE_LIB}
  MinimalSocket
  Threads::Threads
  util  # for openpty()
  # CLI11::CLI11      # uncomment if enabled CLI11 above
)

if (SCALLOP_HAS_KEYSTONE)
  target_link_libraries(scallop PRIVATE ${SCALLOP_KEYSTONE_TARGET})
  target_include_directories(scallop PRIVATE ${SCALLOP_KEYSTONE_INCLUDE_DIR})
  target_compile_definitions(scallop PRIVATE SCALLOP_HAS_KEYSTONE=1)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(scallop PRIVATE -Wall -Wextra -Wpedantic)
endif()
