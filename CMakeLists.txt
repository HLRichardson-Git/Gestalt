cmake_minimum_required(VERSION 3.27.2)

set (This Gestalt)

project (${This} VERSION 0.1.1)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_testing ()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

set (Headers
    src/lib.h
    src/aes/aes.h
    src/aes/aesConstants.h
    src/modes/modes.h
    tools/utils.h
)

set (Sources
    src/lib.cpp
    src/aes/aes.cpp
    src/modes/ecb.cpp
    src/modes/cbc.cpp
    tools/utils.cpp
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library (${This} STATIC ${Sources} ${Headers})
target_link_libraries(${This} gtest_main)

add_subdirectory(tests)