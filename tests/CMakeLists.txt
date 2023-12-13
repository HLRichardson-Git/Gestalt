cmake_minimum_required(VERSION 3.27.2)

set (This tests)

set (Sources
    tests.cpp
)

add_executable (${This} ${Sources})
target_link_libraries (${This} PRIVATE
    gtest_main
    Gestalt
)

add_test (
    NAME ${This}
    COMMAND ${This}
)