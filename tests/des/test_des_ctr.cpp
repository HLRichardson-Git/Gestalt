/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_des_ctr.cpp
 *
 */

#include "gtest/gtest.h"

#include "utils.h"
#include <gestalt/des.h>
#include "vectors/vectors_des_ctr.h"

TEST_P(DES_CTR_Test, encrypt) {
    const DES_CTR_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = encryptDESCTR(SecureBytes::fromHex(test.pt), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));
    
    EXPECT_EQ(result, SecureBytes::fromHex(test.ct));
}

TEST_P(DES_CTR_Test, decrypt) {
    const DES_CTR_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = decryptDESCTR(SecureBytes::fromHex(test.ct), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));
    
    EXPECT_EQ(result, SecureBytes::fromHex(test.pt));
}
