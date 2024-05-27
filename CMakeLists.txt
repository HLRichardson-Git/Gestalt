cmake_minimum_required(VERSION 3.16.3)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

set (Project_Name Gestalt)
project (${Project_Name} VERSION 0.3.1 LANGUAGES C CXX)

set(FETCHCONTENT_BASE_DIR "${CMAKE_BINARY_DIR}/external")
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

enable_testing ()

include(FetchContent)
include(ExternalProject)

add_subdirectory(external/googletest)
add_subdirectory(external/gmp)

set (Sources
    src/aes/aes.cpp
    src/aes/aesCore.cpp
    src/modes/ecb.cpp
    src/modes/cbc.cpp
    src/sha1/sha1.cpp
    src/sha1/sha1Core.cpp
    src/ecc/ecc.cpp
    src/ecc/ecdsa/ecdsa.cpp
    src/ecc/ecdh/ecdh.cpp
    tools/utils.cpp
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library (${Project_Name} STATIC ${Sources})

# Specify the directories where header files are located
target_include_directories(${Project_Name} PUBLIC  ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${Project_Name} PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(${Project_Name} PRIVATE ${PROJECT_SOURCE_DIR}/external)
target_include_directories(${Project_Name} PRIVATE ${PROJECT_SOURCE_DIR}/tools)
target_include_directories(${Project_Name} PRIVATE ${MPIR_INCLUDE_DIR})

# Link MPIR library
add_dependencies(${Project_Name} mpir)
target_link_libraries(${Project_Name} PRIVATE ${MPIR_LIBRARY})

target_link_libraries(${Project_Name} PRIVATE gtest_main)
add_subdirectory(tests)