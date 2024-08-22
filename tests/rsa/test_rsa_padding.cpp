/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_padding.cpp
 *
 */

#include "gtest/gtest.h"
#include <iostream> // for debugging

//#include <gestalt/rsa.h>
#include "rsa/padding_schemes/oaep/oaep.h"
//#include "vectors/vectors_rsa.h"

TEST(RSA_Padding, oaep) {
    std::string input = "Hello, Gestalt!";
    std::string output = applyOAEP_Padding(input, 256);
    std::cout << output << std::endl;
    EXPECT_EQ(output.length(), 26);
}