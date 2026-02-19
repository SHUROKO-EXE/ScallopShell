cmake_minimum_required(VERSION 3.15)
project(scallop_decomp LANGUAGES CXX)

# top-level CMakeLists.txt
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Debug if not set by caller
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

include(FetchContent)

# --- Minimal-Socket ---
set(MIN_SOCKET_SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/min_sock-src")
if (NOT EXISTS "${MIN_SOCKET_SOURCE_DIR}/CMakeLists.txt")
  message(STATUS "Minimal-Socket not found — downloading...")
  set(BUILD_MinimalCppSocket_SAMPLES OFF CACHE BOOL "" FORCE)
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

# --- Sources ---
file(GLOB_RECURSE SCALLOP_DECOMP_SOURCES
     CONFIGURE_DEPENDS
     "${CMAKE_SOURCE_DIR}/src/*.cpp"
     "${CMAKE_SOURCE_DIR}/src/decompilerAPI/*.cpp")

add_executable(scallop_decomp ${SCALLOP_DECOMP_SOURCES})

# --- Includes ---
target_include_directories(scallop_decomp PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include/decompilerAPI
  ${CMAKE_SOURCE_DIR}/../include
)

# --- Capstone ---
find_library(CAPSTONE_LIB capstone REQUIRED)

# --- Threads ---
find_package(Threads REQUIRED)

# --- LLVM ---
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
llvm_map_components_to_libnames(LLVM_LIBS
  Core
  Support
  Target
  MC
  MCParser
  CodeGen
  AsmPrinter
  AsmParser
  AllTargetsCodeGens
  AllTargetsAsmParsers
  AllTargetsDisassemblers
)

# --- Link ---
target_link_libraries(scallop_decomp PRIVATE
  ${CAPSTONE_LIB}
  ${LLVM_LIBS}
  MinimalSocket
  Threads::Threads
)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(scallop_decomp PRIVATE -Wall -Wextra -Wpedantic)
endif()
