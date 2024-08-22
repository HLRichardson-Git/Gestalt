cmake_minimum_required(VERSION 3.16.3)

include(GoogleTest)

set (This tests)

set (Sources
    aes/test_aes_ecb.cpp
    aes/test_aes_cbc.cpp
    aes/test_aes_functions.cpp
    des/test_des_ecb.cpp
    des/test_tdes_ecb.cpp
    des/test_des_cbc.cpp
    des/test_tdes_cbc.cpp
    des/test_des_functions.cpp
    ecc/test_ecc_functions.cpp
    ecc/test_ecdsa.cpp
    ecc/test_ecdsa_functions.cpp
    ecc/test_ecdh.cpp
    ecc/test_ecdh_functions.cpp
    rsa/test_rsa.cpp
    rsa/test_rsa_padding.cpp
    rsa/test_rsa_key_generation.cpp
    rsa/test_rsa_prime_generation.cpp
    hmac/test_hmac.cpp
    sha1/test_sha1.cpp
    sha1/test_sha1_functions.cpp
    sha2/test_sha2.cpp
)

add_executable (${This} ${Sources})

target_include_directories(${This}
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/tools
)

target_link_libraries (${This} 
    PRIVATE
        GTest::gtest_main
        Gestalt
)

add_test (
    NAME ${This}
    COMMAND ${This}
)

include(GoogleTest)
gtest_discover_tests(${This})