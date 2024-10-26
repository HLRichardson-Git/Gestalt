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

std::string encodePSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes) {
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

bool verifyPSS_Padding(const std::string& EM, const std::string& message, const PSSParams& params, unsigned int modulusSizeBytes) {
    if (static_cast<unsigned char>(EM[EM.length() - 1]) != 0xbc) {
        //std::cout << "Result = " << static_cast<unsigned char>(EM[EM.length() - 1]) << std::endl;
        throw std::invalid_argument("Given PSS encoded message does not end with 0xbc");
    }

    std::string mHash = hexToBytes(hash(message, params.hashFunc));
    std::cout << "mHash = " << convertToHex(mHash) << std::endl;
    
    int emLen = calculateEmLen((modulusSizeBytes * 8) - 1);
    unsigned int hLen = static_cast<unsigned int>(params.hashFunc);
    std::string maskedDB = EM.substr(0, emLen - hLen - 1);
    std::cout << "maskedDB = " << convertToHex(maskedDB) << std::endl;
    std::string H = EM.substr(emLen - hLen - 1, hLen);
    std::cout << "H = " << convertToHex(H) << std::endl;

    std::string dbMask = hexToBytes(mgf1(H, emLen - hLen - 1, params.hashFunc));
    std::cout << "dbMask = " << convertToHex(dbMask) << std::endl;
    std::string DB;
    for (size_t i = 0; i < maskedDB.length(); ++i) {
        DB += maskedDB[i] ^ dbMask[i];
    }
    std::cout << "DB = " << convertToHex(DB) << std::endl;

    std::string salt = DB.substr(DB.length() - params.sLen, params.sLen);
    std::cout << "salt = " << convertToHex(salt) << std::endl;

    std::string PS1(PADDING1_SIZE, 0x00);
    std::string mPrime = PS1 + mHash + salt;
    std::cout << "mPrime = " << convertToHex(mPrime) << std::endl;

    std::string hPrime = hexToBytes(hash(mPrime, params.hashFunc));
    std::cout << "hPrime = " << convertToHex(hPrime) << std::endl;
    
    if (H == hPrime) return true;

    return false;
}