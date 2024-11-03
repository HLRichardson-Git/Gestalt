/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_pkcs1v15.cpp
 *
 */

#include "gtest/gtest.h"

#include <gestalt/rsa.h>
#include "utils.h"
#include "rsa/padding_schemes/rsa_padding.h"
#include "rsa/padding_schemes/pkcs1v15/pkcs1v15.h"
#include "vectors/vectors_rsa_pkcs1v15.h"

const std::string inputMsg = 
    "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf7"
    "8b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc";
const std::string expectedEncodedMessage = 
    "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d"
    "3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc8"
    "16d97cd7a2c43bad546fbe8cfebc";

TEST(RSA_PKCS1v15, encodeForEncryption) {
    std::string result = encodeForEncryptionPKCS1v15(hexToBytes(inputMsg));
    EXPECT_EQ(convertToHex(result), expectedEncodedMessage);
}