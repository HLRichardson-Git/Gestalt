cmake_minimum_required(VERSION 3.16.3)

#set (Project_Name Gestalt)
#project (${Project_Name} VERSION 0.3.1 LANGUAGES C CXX)
#project (${Project_Name} VERSION 0.3.1 LANGUAGES CXX)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

set (Project_Name Gestalt)
project (${Project_Name} VERSION 0.3.1 LANGUAGES C CXX)

set(FETCHCONTENT_BASE_DIR "${CMAKE_BINARY_DIR}/external")
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

enable_testing ()

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

#FetchContent_Declare(
#  gmp
#  URL https://gmplib.org/download/gmp/gmp-6.3.0.tar.lz
#)

#FetchContent_Declare(
#    Boost
#    #URL https://github.com/boostorg/boost/archive/refs/tags/boost-1.61.0.zip
#    URL https://github.com/boostorg/boost/archive/refs/tags/boost-1.85.0.zip
#)
#set(Boost_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/build/_deps/boost-src/tools/cmake/include")

#FetchContent_Declare(
#    ctbignum
#    URL https://github.com/niekbouman/ctbignum/archive/refs/tags/v0.7.zip
#)

set (Sources
    src/aes/aes.cpp
    src/aes/aesCore.cpp
    src/modes/ecb.cpp
    src/modes/cbc.cpp
    src/sha1/sha1.cpp
    src/sha1/sha1Core.cpp
    src/ecc/ecc.cpp
    src/ecc/ecdsa/ecdsa.cpp
    tools/utils.cpp
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

#set(GMP_SKIP_BUILD_TEST ON CACHE BOOL "")
#set(GMP_ENABLE_DESKTOP 0 CACHE BOOL "")
#FetchContent_MakeAvailable(gmp)
#FetchContent_MakeAvailable(Boost)
#FetchContent_MakeAvailable(ctbignum)

add_library (${Project_Name} STATIC ${Sources})
# Specify the directories where header files are located
target_include_directories(${Project_Name} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${Project_Name} PRIVATE ${PROJECT_SOURCE_DIR}/external)
target_include_directories(${Project_Name} PRIVATE ${PROJECT_SOURCE_DIR}/tools)
#target_include_directories(${Project_Name} PRIVATE ${PROJECT_SOURCE_DIR}/external/ctbignum)

add_subdirectory(external/infint)
#add_subdirectory(external/boost)
#add_subdirectory(external/ctbignum)

target_link_libraries(${Project_Name} PRIVATE gtest_main)
#target_link_libraries(${Project_Name} PRIVATE gmp::gmp)
#target_link_libraries(${Project_Name} PRIVATE infint)
#target_link_libraries(${Project_Name} PRIVATE gmp)
#target_link_libraries(${Project_Name} PRIVATE ctbignum)

add_subdirectory(tests)