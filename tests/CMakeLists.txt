cmake_minimum_required(VERSION 3.16.3)

include(GoogleTest)

set (This tests)

set (Sources
    aesTests.cpp
    desTests.cpp
    sha1Tests.cpp
    sha2Tests.cpp
    eccTests.cpp
    ecdsaTests.cpp
    ecdhTests.cpp
)

add_executable (${This} ${Sources})

target_include_directories(${This} PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(${This} PRIVATE ${MPIR_INCLUDE_DIR})

target_link_libraries (${This} PRIVATE
    GTest::gtest_main
    ${MPIR_LIBRARY}
    Gestalt
)

add_test (
    NAME ${This}
    COMMAND ${This}
)

include(GoogleTest)
gtest_discover_tests(${This})