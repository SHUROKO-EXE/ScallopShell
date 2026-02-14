cmake_minimum_required(VERSION 3.16)

project(refactorscallop LANGUAGES C CXX)

# Position independent code is needed for a plugin .so
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# === QEMU paths (you MUST set these when configuring) ===
set(QEMU_SRC "" CACHE PATH "Path to the QEMU source tree")
set(QEMU_BUILD "" CACHE PATH "Path to the QEMU build tree (where you ran ./configure && make)")

if(NOT QEMU_SRC)
    message(FATAL_ERROR "QEMU_SRC is not set. Pass -DQEMU_SRC=/path/to/qemu to CMake.")
endif()

if(NOT QEMU_BUILD)
    message(FATAL_ERROR "QEMU_BUILD is not set. Pass -DQEMU_BUILD=/path/to/qemu/build to CMake.")
endif()

# === MinimalSocket via FetchContent ===
include(FetchContent)

# Disable MinimalSocket samples
set(BUILD_MinimalCppSocket_SAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    min_sock
    GIT_REPOSITORY https://github.com/andreacasalino/Minimal-Socket
    GIT_TAG        master
)

FetchContent_MakeAvailable(min_sock)

# === Find glib-2.0 (like your pkg-config line) ===
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)

# === LLVM (prefer CMake package config, fallback to llvm-config) ===
set(SCALLOP_LLVM_INCLUDE_DIRS "")
set(SCALLOP_LLVM_DEFINITIONS "")
set(SCALLOP_LLVM_COMPILE_OPTIONS "")
set(SCALLOP_LLVM_LIBS "")

find_package(LLVM CONFIG QUIET)
if(LLVM_FOUND)
    set(SCALLOP_LLVM_INCLUDE_DIRS ${LLVM_INCLUDE_DIRS})
    set(SCALLOP_LLVM_DEFINITIONS ${LLVM_DEFINITIONS})

    if(TARGET LLVM::Object)
        list(APPEND SCALLOP_LLVM_LIBS LLVM::Object)
        if(TARGET LLVM::DebugInfoDWARF)
            list(APPEND SCALLOP_LLVM_LIBS LLVM::DebugInfoDWARF)
        endif()
        if(TARGET LLVM::Symbolize)
            list(APPEND SCALLOP_LLVM_LIBS LLVM::Symbolize)
        endif()
        if(TARGET LLVM::Demangle)
            list(APPEND SCALLOP_LLVM_LIBS LLVM::Demangle)
        endif()
        if(TARGET LLVM::Support)
            list(APPEND SCALLOP_LLVM_LIBS LLVM::Support)
        endif()
    elseif(COMMAND llvm_map_components_to_libnames)
        llvm_map_components_to_libnames(SCALLOP_LLVM_LIBS
            Object
            DebugInfoDWARF
            Symbolize
            Demangle
            Support
        )
    else()
        message(FATAL_ERROR "Found LLVM, but no usable LLVM imported targets or component mapping API.")
    endif()
else()
    find_program(LLVM_CONFIG_EXECUTABLE
        NAMES llvm-config llvm-config-19 llvm-config-18 llvm-config-17 llvm-config-16 llvm-config-15 llvm-config-14
    )
    if(NOT LLVM_CONFIG_EXECUTABLE)
        message(FATAL_ERROR
            "Could not find LLVM via CMake package config or llvm-config.\n"
            "Install LLVM development files (e.g. llvm-devel / llvm-dev), or set LLVM_DIR."
        )
    endif()

    execute_process(
        COMMAND ${LLVM_CONFIG_EXECUTABLE} --includedir
        OUTPUT_VARIABLE LLVM_INCLUDEDIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${LLVM_CONFIG_EXECUTABLE} --cxxflags
        OUTPUT_VARIABLE LLVM_CXXFLAGS_RAW
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${LLVM_CONFIG_EXECUTABLE} --ldflags
        OUTPUT_VARIABLE LLVM_LDFLAGS_RAW
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${LLVM_CONFIG_EXECUTABLE} --libs
        OUTPUT_VARIABLE LLVM_LIBS_RAW
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${LLVM_CONFIG_EXECUTABLE} --system-libs
        OUTPUT_VARIABLE LLVM_SYSTEM_LIBS_RAW
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    set(SCALLOP_LLVM_INCLUDE_DIRS ${LLVM_INCLUDEDIR})
    separate_arguments(SCALLOP_LLVM_COMPILE_OPTIONS NATIVE_COMMAND "${LLVM_CXXFLAGS_RAW}")
    separate_arguments(LLVM_LDFLAGS_LIST NATIVE_COMMAND "${LLVM_LDFLAGS_RAW}")
    separate_arguments(LLVM_LIBS_LIST NATIVE_COMMAND "${LLVM_LIBS_RAW}")
    separate_arguments(LLVM_SYSTEM_LIBS_LIST NATIVE_COMMAND "${LLVM_SYSTEM_LIBS_RAW}")
    list(APPEND SCALLOP_LLVM_LIBS
        ${LLVM_LDFLAGS_LIST}
        ${LLVM_LIBS_LIST}
        ${LLVM_SYSTEM_LIBS_LIST}
    )
endif()

# === Sources ===
# C sources at top level (e.g. disasm.c)
file(GLOB PLUGIN_C_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)

# C++ sources at top level and in src/
file(GLOB PLUGIN_CPP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(refactorscallop SHARED
    ${PLUGIN_C_SOURCES}
    ${PLUGIN_CPP_SOURCES}
)

# If you want a specific C++ standard
set_target_properties(refactorscallop PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    OUTPUT_NAME "refactorscallop"  # produces librefactorscallop.so
)

# === Include directories ===
target_include_directories(refactorscallop
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${QEMU_SRC}/include
        ${QEMU_BUILD}/include
        ${GLIB2_INCLUDE_DIRS}
        ${SCALLOP_LLVM_INCLUDE_DIRS}
)

# Extra GLib flags (warnings, defines, etc.)
target_compile_options(refactorscallop PRIVATE ${GLIB2_CFLAGS_OTHER} ${SCALLOP_LLVM_COMPILE_OPTIONS})
target_compile_definitions(refactorscallop PRIVATE ${SCALLOP_LLVM_DEFINITIONS})

# === Linking ===
target_link_libraries(refactorscallop
    PRIVATE
        ${GLIB2_LIBRARIES}
        pthread
        MinimalSocket
        ${SCALLOP_LLVM_LIBS}
)
