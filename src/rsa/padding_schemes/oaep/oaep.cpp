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
        seed = generateRandomHexData(hashLength);
    }
    std::cout << "seed: " << seed << std::endl;
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
    std::cout << "seed: " << seed << std::endl;
    std::string maskedSeed;
    seed = hexToBytes(seed);
    for (size_t i = 0; i < hashLength; ++i) {
        maskedSeed += seed[i] ^ seedMask[i];
    }
    std::cout << "maskedSeed = seed xor seedMask: " << convertToHex(maskedSeed) << std::endl;

    return std::string(1, 0x00) + maskedSeed + maskedDB; // EM
}

std::string removeOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes) {
    if (static_cast<unsigned char>(input[0]) != 0x00) {
        throw std::invalid_argument("Given OAEP message does not begin with 0x00");
    }
    std::string lhash = hexToBytes(hash(params.label, params.hashFunc));
    std::cout << "lhash = " << convertToHex(lhash) << std::endl;

    std::cout << "input = " << convertToHex(input) << std::endl;
    unsigned int hashLength = static_cast<unsigned int>(params.hashFunc);
    std::string maskedSeed = input.substr(1, hashLength);
    std::cout << "maskedSeed = " << convertToHex(maskedSeed) << std::endl;

    std::string maskedDB = input.substr(hashLength + 1, input.length());
    std::cout << "maskedDB = " << convertToHex(maskedDB) << std::endl;

    std::string seedMask = hexToBytes(mgf1(maskedDB, hashLength, params.hashFunc));
    std::cout << "seedMask = MGF(maskedDB, length(seed)): " << convertToHex(seedMask) << std::endl; 

    std::string seed = "";
    for (size_t i = 0; i < seedMask.length(); ++i) {
        seed += maskedSeed[i] ^ seedMask[i];
    }
    std::cout << "seed = maskedSeed xor seedMask: " << convertToHex(seed) << std::endl;

    std::string dbMask = hexToBytes(mgf1(seed, modulusSizeBytes - hashLength - 1, params.hashFunc));
    std::cout << "dbMask = MGF(seed, length(DB)): " << convertToHex(dbMask) << std::endl;

    std::string DB;
    for (size_t i = 0; i < maskedDB.length(); ++i) {
        DB += maskedDB[i] ^ dbMask[i];
    }
    std::cout << "DB = maskedDB xor dbMask: " << convertToHex(DB) << std::endl;
    std::cout << "lhash from DB = " << convertToHex(DB.substr(0, hashLength)) << std::endl;
    std::cout << "lhash = " << convertToHex(lhash) << std::endl;
    if (DB.substr(0, hashLength) != lhash) {
        throw std::invalid_argument("OAEP Decode Error: The encoded lhash and computed lhash are not the same.");
    }
    std::cout << "GOt here? " << std::endl;
    // Compute the length of PS
    int psStartPos = hashLength + 1;  // Padding starts after lhash and the 0x01 delimiter
    int psEndPos = DB.find(0x01, psStartPos);  // Look for the 0x01 byte which ends PS

    if (psEndPos == std::string::npos || psEndPos <= psStartPos) {
        throw std::invalid_argument("OAEP Decode Error: Padding 0x01 byte not found.");
    }

    // Ensure all bytes from psStartPos to psEndPos-1 are zero (the PS)
    for (int i = psStartPos; i < psEndPos; i++) {
        if (DB[i] != 0x00) {
            throw std::invalid_argument("OAEP Decode Error: Non-zero byte found in padding (PS).");
        }
    }
    std::cout << "GOt here? 3" << std::endl;
    std::string message = DB.substr(psEndPos + 1, DB.length());
    std::cout << "Message = " << convertToHex(message) << std::endl;

    return message;
}