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
#include <gestalt/sha2.h>
#include "../rsa_padding.h"

std::string applyOAEP_Padding(const std::string& input, const std::string& label, unsigned int k) {
    unsigned int h = SHA256_LENGTH;
    unsigned int inputLength = input.length(); // This inheriently means it can only handle ASCII for now

    int psLen = k - inputLength - (2 * h) - 2;
    std::cout << "psLen length: " << psLen << std::endl;
    if (psLen < 0) {
        throw std::invalid_argument("Message too long for RSA modulus");
    }
    std::string PS(psLen, 0x00);
    
    // TODO: convert the output of hashSHA256 to bytes because you will find that the DB length is 255
    // because it is doing it correctly, but since the output of hashSHA256 is in hex, and the length of DB
    // is expected as bytes its "counting the byte twice", so its adding 32 to the length
    // Maybe this is an overall flaw of the SHA implementations I have...
    std::string DB = hashSHA256(label) + PS + "\x01" + input;
    std::cout << "DB: " << DB << std::endl;
    std::cout << "DB length: " << DB.length() << std::endl;

    //std::string seed = generateRandomBytes(h);
    std::string seed = "vSjdQHwCbOAFdaFUpyGNSelPecnnExOV"; // Hard coding seed for testing purposes 

    std::string dbMask = MGF1(seed, k - h - 1);
    std::cout << "dbMask length: " << dbMask.length() << std::endl;
    
    std::string maskedDB;
    for (size_t i = 0; i < DB.length(); ++i) {
        maskedDB += DB[i] ^ dbMask[i];
    }

    std::string seedMask = MGF1(maskedDB, h);

    std::string maskedSeed;
    for (size_t i = 0; i < h; ++i) {
        maskedSeed += seed[i] ^ seedMask[i];
    }
    std::cout << "got here 2" << std::endl;
    return std::string(1, 0x00) + maskedSeed + maskedDB; // EM
}

std::string applyOAEP_Padding(const std::string& input, unsigned int k) {
    return applyOAEP_Padding(input, "", k);
}