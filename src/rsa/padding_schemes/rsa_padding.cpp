/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
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

#include <string>

#include "rsa_padding.h"

std::string mgf1(const std::string& seed, unsigned int maskLen, HashAlgorithm hashAlg) {
    unsigned int hashLength = static_cast<unsigned int>(hashAlg);
    std::string mask = "";
    unsigned char C[4];
    int iterations = (maskLen + hashLength - 1) / hashLength; // This is the same as ceil(maskLen/ SHA256_LENGTH)

    for (int i = 0; i < iterations; i++) {
        // Construct the counter C
        C[0] = (i >> 24) & 0xFF;
        C[1] = (i >> 16) & 0xFF;
        C[2] = (i >> 8) & 0xFF;
        C[3] = i & 0xFF;

        std::string computedHash = hash(hashAlg)(seed + std::string(reinterpret_cast<char*>(C), 4));
        mask += computedHash;
    }

    return mask.substr(0, maskLen * 2); // mask is in hex, but we need bytes so we double the maskLen
}