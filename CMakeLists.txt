# Main CMakeLists
cmake_minimum_required(VERSION 3.15)

# Project Name
project(ExHIBIT_KeyFinder)

# Option
set(USER_CONFIG_BUILD_TEST TRUE)
set(USER_CONFIG_IPO_OPTIMIZATION TRUE)
set(USER_CONFIG_STATIC_MSVC_RUNTIME TRUE)

# Value Define
set(ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}")

# Out Path
if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(EXECUTABLE_OUTPUT_PATH "${ROOT_DIR}/.bin/x32")
    set(LIBRARY_OUTPUT_PATH "${ROOT_DIR}/.bin/x32")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(EXECUTABLE_OUTPUT_PATH "${ROOT_DIR}/.bin/x64")
    set(LIBRARY_OUTPUT_PATH "${ROOT_DIR}/.bin/x64")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(EXECUTABLE_OUTPUT_PATH "${EXECUTABLE_OUTPUT_PATH}/debug")
    set(LIBRARY_OUTPUT_PATH "${LIBRARY_OUTPUT_PATH}/debug")
else()
    set(EXECUTABLE_OUTPUT_PATH "${EXECUTABLE_OUTPUT_PATH}/release")
    set(LIBRARY_OUTPUT_PATH "${LIBRARY_OUTPUT_PATH}/release")
endif()

# IPO
if(USER_CONFIG_IPO_OPTIMIZATION)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_check_result OUTPUT output)
    if(ipo_check_result)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL TRUE)
    else()
        message(WARNING "IPO is not supported: ${output}")
    endif()
endif()

# MSVC Setting
if(MSVC)
    # Macro
    add_definitions(-DUNICODE -D_UNICODE)
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")

    # Runtime
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        if (USER_CONFIG_STATIC_MSVC_RUNTIME)
            set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDebug)
        else()
            set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDebugDLL)
        endif()
    else()
        if (USER_CONFIG_STATIC_MSVC_RUNTIME)
            set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
        else()
            set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
        endif()
    endif()

    # Compiler
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        # set(CMAKE_CXX_FLAGS_DEBUG)
    else()
        add_link_options(/OPT:REF)
        set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Gy /GS /Zc:inline /Zc:forScope")
        # set(CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        # set(CMAKE_CXX_FLAGS_MINSIZEREL)
    endif()
endif()

# Include
include_directories("${ROOT_DIR}")

# Library
add_subdirectory("lib")
add_subdirectory("src")
