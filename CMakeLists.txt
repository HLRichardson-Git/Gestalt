cmake_minimum_required(VERSION 3.16.3)

# Project setup
project (Gestalt VERSION 0.7 LANGUAGES C CXX)
set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options for toggling features
option(GESTALT_BUILD_TESTS "Build unit tests" ON)
option(GESTALT_FETCH_MPIR "Fetch MPIR library automatically" ON)
option(GESTALT_FETCH_GOOGLETEST "Fetch GoogleTest library automatically" ON)

set(FETCHCONTENT_BASE_DIR "${CMAKE_BINARY_DIR}/external")
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# Include required modules
include(FetchContent)
include(ExternalProject)

set (Sources
    src/aes/aes.cpp
    src/aes/aesCore.cpp
    src/des/des.cpp
    src/des/desCore.cpp
    src/sha1/sha1.cpp
    src/sha1/sha1Core.cpp
    src/sha2/sha2.cpp
    src/hmac/hmac.cpp
    src/ecc/ecc.cpp
    src/ecc/ecdsa/ecdsa.cpp
    src/ecc/ecdh/ecdh.cpp
    src/rsa/rsa.cpp
    src/rsa/rsaObjects.cpp
    src/rsa/padding_schemes/oaep/oaep.cpp
    src/rsa/padding_schemes/pss/pss.cpp
    src/rsa/padding_schemes/rsa_padding.cpp
    src/rsa/prime_generation/prime_generation.cpp
    src/rsa/rsa_key_generation/rsaKeyGen.cpp
    tools/utils.cpp
)

add_library (${PROJECT_NAME} STATIC ${Sources})

# Specify the directories where header files are located
target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/external
        ${PROJECT_SOURCE_DIR}/tools
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

# Conditionally fetch or find MPIR
if(GESTALT_FETCH_MPIR)
    add_subdirectory(external/gmp)
    set(MPIR_LIB_TARGET mpir)
    add_dependencies(${PROJECT_NAME} mpir)
else()
    find_package(MPIR REQUIRED)
    if(NOT MPIR_FOUND)
        message(FATAL_ERROR "MPIR library not found. Please install MPIR or set FETCH_MPIR to ON.")
    endif()
    set(MPIR_INCLUDE_DIR ${MPIR_INCLUDE_DIR})
    set(MPIR_LIBRARY ${MPIR_LIBRARY})
endif()

# Link MPIR library
target_include_directories(${PROJECT_NAME} PUBLIC ${MPIR_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC ${MPIR_LIBRARY})

# Enable testing and include GoogleTest if GESTALT_BUILD_TESTS is ON
if(GESTALT_BUILD_TESTS)
    enable_testing()

    if(GESTALT_FETCH_GOOGLETEST)
        add_subdirectory(external/googletest)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    else()
        # Find GoogleTest
        find_package(GTest REQUIRED)
        if(NOT GTest_FOUND)
            message(FATAL_ERROR "GoogleTest not found. Please provide GoogleTest or set GESTALT_FETCH_GOOGLETEST to ON.")
        endif()
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE gtest_main)
    add_subdirectory(tests)
endif()