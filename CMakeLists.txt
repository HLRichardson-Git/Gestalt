cmake_minimum_required(VERSION 3.27.2)

set (This Gestalt)

project (${This} C CXX)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_testing ()

add_subdirectory (googletest)

set (Headers
    src/lib.h
    src/aes/aes.h
    src/aes/aesConstants.h
    tools/utils.h
)

set (Sources
    src/lib.cpp
    src/aes/aes.cpp
    tools/utils.cpp
)

add_library (${This} STATIC ${Sources} ${Headers})

add_subdirectory(tests)