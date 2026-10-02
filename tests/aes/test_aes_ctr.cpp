/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_ctr.cpp
 *
 */

#include "gtest/gtest.h"

#include "utils.h"
#include <gestalt/aes.h>
#include "vectors/vectors_aes_ctr.h"

TEST_P(AES_CTR_Test, encrypt) {
    const AES_CTR_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = encryptAESCTR(SecureBytes::fromHex(test.pt), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));
    
    EXPECT_EQ(result, SecureBytes::fromHex(test.ct));
}

TEST_P(AES_CTR_Test, decrypt) {
    const AES_CTR_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = decryptAESCTR(SecureBytes::fromHex(test.ct), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));
    
    EXPECT_EQ(result, SecureBytes::fromHex(test.pt));
}
