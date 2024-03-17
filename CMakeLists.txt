cmake_minimum_required(VERSION 3.16.3)

set (Project_Name Gestalt)
project (${Project_Name} VERSION 0.3 LANGUAGES C CXX)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_testing ()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

set (Sources
    src/aes/aes.cpp
    src/aes/aesCore.cpp
    src/modes/ecb.cpp
    src/modes/cbc.cpp
    src/sha1/sha1.cpp
    src/sha1/sha1Core.cpp
    tools/utils.cpp
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library (${Project_Name} STATIC ${Sources})
# Specify the directories where header files are located
target_include_directories(${Project_Name} PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(${Project_Name} gtest_main)

add_subdirectory(tests)