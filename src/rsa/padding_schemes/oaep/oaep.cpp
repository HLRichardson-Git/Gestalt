/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * oaep.cpp
 *
 */

#include <iostream>
#include <string>

#include "oaep.h"
#include <gestalt/sha1.h>
#include <gestalt/sha2.h>
#include "utils.h"

std::string applyOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes) {
    unsigned int hashLength = static_cast<unsigned int>(params.hashFunc);
    std::cout << "mod size: " << modulusSizeBytes << std::endl;
    unsigned int inputLength = input.length(); // This inheriently means it can only handle ASCII for now
    std::cout << "input length: " << inputLength << std::endl;
    int psLen = modulusSizeBytes - inputLength - (2 * hashLength) - 2;
    std::cout << "psLen length in bytes: " << psLen << std::endl;
    if (psLen < 0) {
        throw std::invalid_argument("Message too long for RSA modulus");
    }
    std::string PS(psLen, 0x00);
    std::cout << "PS length in bytes: " << PS.length() << std::endl;
    // TODO: convert the output of hashSHA256 to bytes because you will find that the DB length is 255
    // because it is doing it correctly, but since the output of hashSHA256 is in hex, and the length of DB
    // is expected as bytes its "counting the byte twice", so its adding 32 to the length
    // Maybe this is an overall flaw of the SHA implementations I have...
    std::string DB = hexToBytes(hash(params.label, params.hashFunc)) + PS + "\x01" + input;
    std::cout << "DB = pHash || Padding || M: " << convertToHex(DB) << std::endl;
    //std::cout << "DB length in bytes: " << DB.length() << std::endl;

    std::string seed = params.seed;
    if (seed.empty()) {
        //seed = generateRandomBytes(h);
    }

    std::string dbMask = hexToBytes(mgf1(hexToBytes(seed), modulusSizeBytes - hashLength - 1, params.hashFunc));
    std::cout << "dbMask = MGF(seed, length(DB)): " << convertToHex(dbMask) << std::endl;
    //std::cout << "dbMask length: " << dbMask.length() << std::endl;
    
    std::string maskedDB;
    for (size_t i = 0; i < DB.length(); ++i) {
        maskedDB += DB[i] ^ dbMask[i];
    }
    std::cout << "maskedDB = DB xor dbMask: " << convertToHex(maskedDB) << std::endl;

    std::string seedMask = hexToBytes(mgf1(maskedDB, hashLength, params.hashFunc));
    std::cout << "seedMask = MGF(maskedDB, length(seed)): " << convertToHex(seedMask) << std::endl;   

    std::string maskedSeed;
    seed = hexToBytes(seed);
    for (size_t i = 0; i < hashLength; ++i) {
        maskedSeed += seed[i] ^ seedMask[i];
    }
    std::cout << "maskedSeed = seed xor seedMask: " << convertToHex(maskedSeed) << std::endl;

    return std::string(1, 0x00) + maskedSeed + maskedDB; // EM
}