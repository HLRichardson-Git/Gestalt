# CMakeLists.txt for compiling InfInt library

set (This infint)
add_library(${This} STATIC main.cpp)
target_link_libraries (${This} PRIVATE Gestalt)
target_include_directories(${This} PUBLIC ${PROJECT_SOURCE_DIR})
