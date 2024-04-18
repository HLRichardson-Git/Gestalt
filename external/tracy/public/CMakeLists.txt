# CMakeLists.txt for compiling Tracy library

set (This tracy)
add_library(${This} STATIC TracyClient.cpp)
target_compile_definitions(${This} PUBLIC TRACY_ENABLE)
#target_link_libraries (${This} PRIVATE Gestalt)
target_include_directories(${This} PUBLIC ${PROJECT_SOURCE_DIR})