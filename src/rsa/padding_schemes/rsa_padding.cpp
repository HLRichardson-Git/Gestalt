/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa_padding.cpp
 *
 * This file implements the Mask Generation Function (MGF1), which generates a mask of a specified length based on a 
 * given seed and hash algorithm (such as SHA1, SHA256, etc.). The MGF1 function is commonly used in cryptographic 
 * protocols like RSA-PSS and OAEP.
 * 
 */

#include <algorithm>
#include <vector>

#include "rsa_padding.h"

SecureBytes mgf1(const SecureBytes& seed, unsigned int maskLen, HashAlgorithm hashAlg) {
    unsigned int hashLength = static_cast<unsigned int>(hashAlg);
    SecureBytes mask;
    unsigned char C[4];
    int iterations = (maskLen + hashLength - 1) / hashLength; // ceil(maskLen / hashLength)

    for (int i = 0; i < iterations; i++) {
        // Construct the counter C
        C[0] = (i >> 24) & 0xFF;
        C[1] = (i >> 16) & 0xFF;
        C[2] = (i >> 8) & 0xFF;
        C[3] = i & 0xFF;

        SecureBytes seedWithCounter(seed.size() + 4);
        std::copy(seed.begin(), seed.end(), seedWithCounter.begin());
        std::copy(C, C + 4, seedWithCounter.begin() + seed.size());

        mask.append(hash(hashAlg)(seedWithCounter));
    }

    return SecureBytes::fromVector(std::vector<uint8_t>(mask.begin(), mask.begin() + maskLen));
}