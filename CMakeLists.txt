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
set(KEYSTONE_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/keystone-src")
set(BUILD_LIBS_ONLY ON CACHE BOOL "Only build the Keystone library" FORCE)
set(KEYSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "Do not force static runtime when embedding Keystone" FORCE)
set(SCALLOP_KEYSTONE_INCLUDE_DIR "${KEYSTONE_SOURCE_DIR}/include")

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
endif()

# Uncomment if you also want CLI11 (header-only)
# FetchContent_Declare(
#   CLI11
#   GIT_REPOSITORY https://github.com/CLIUtils/CLI11
#   GIT_TAG        v2.4.2
# )
# FetchContent_MakeAvailable(CLI11)

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
  keystone
  MinimalSocket
  Threads::Threads
  util  # for openpty()
  # CLI11::CLI11      # uncomment if enabled CLI11 above
)

target_include_directories(scallop PRIVATE ${SCALLOP_KEYSTONE_INCLUDE_DIR})
target_compile_definitions(scallop PRIVATE SCALLOP_HAS_KEYSTONE=1)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(scallop PRIVATE -Wall -Wextra -Wpedantic)
endif()
