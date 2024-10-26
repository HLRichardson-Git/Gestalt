/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pss.cpp
 *
 */

#include <iostream>
#include <string>

#include "pss.h"
#include <gestalt/sha1.h>
#include <gestalt/sha2.h>
#include "utils.h"

std::size_t calculateEmLen(std::size_t emBits) {
    return (emBits + 7) / 8;
}

std::string applyPSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes) {
    std::string mHash = hexToBytes(hash(input, params.hashFunc));
    std::cout << "mHash = " << convertToHex(mHash) << std::endl;

    std::string salt = params.salt;
    if (salt.empty()) salt = generateRandomHexData(params.sLen);
    std::cout << "salt = " << salt << std::endl;

    std::string PS1(PADDING1_SIZE, 0x00);

    std::string mPrime = PS1 + mHash + hexToBytes(salt);
    std::cout << "mPrime = " << convertToHex(mPrime) << std::endl;

    std::string H = hexToBytes(hash(mPrime, params.hashFunc));

    int emLen = calculateEmLen((modulusSizeBytes * 8) - 1);
    unsigned int hLen = static_cast<unsigned int>(params.hashFunc);
    int ps2Len = emLen - params.sLen - hLen - 2;
    std::string PS2(ps2Len, 0x00);

    std::string DB = PS2 + "\x01" + hexToBytes(salt);
    std::cout << "DB = " << convertToHex(DB) << std::endl;

    std::string dbMask = hexToBytes(mgf1(H, emLen - hLen - 1, params.hashFunc));
    std::cout << "dbMask = " << convertToHex(dbMask) << std::endl;
    std::string maskedDB;
    for (size_t i = 0; i < DB.length(); ++i) {
        maskedDB += DB[i] ^ dbMask[i];
    }

    // TODO: Step 11 seems confusing????

    std::string EM = maskedDB + H + "\xbc";
    std::cout << "EM = " << convertToHex(EM) << std::endl;

    return EM;
}

std::string removePSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes) {
    
    
    return "";
}