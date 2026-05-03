/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_tdes_ctr.cpp
 *
 */

#include "gtest/gtest.h"

#include "utils.h"
#include <gestalt/des.h>
#include "vectors/vectors_tdes_ctr.h"

TEST_P(TDES_CTR_Test, encrypt) {
    const TDES_CTR_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = encrypt3DESCTR(
        SecureBytes::fromHex(test.pt), 
        SecureBytes::fromHex(test.iv), 
        SecureBytes::fromHex(test.key1), 
        SecureBytes::fromHex(test.key2), 
        SecureBytes::fromHex(test.key3)
    );
    
    EXPECT_EQ(result, SecureBytes::fromHex(test.ct));
}

TEST_P(TDES_CTR_Test, decrypt) {
    const TDES_CTR_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = decrypt3DESCTR(
        SecureBytes::fromHex(test.ct), 
        SecureBytes::fromHex(test.iv), 
        SecureBytes::fromHex(test.key1), 
        SecureBytes::fromHex(test.key2), 
        SecureBytes::fromHex(test.key3)
    );
    
    EXPECT_EQ(result, SecureBytes::fromHex(test.pt));
}
