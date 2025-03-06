/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der.h
 *
 */

# pragma once

#include "rsa/rsa_key_generation/rsaKeyGen.h"

#include <vector>

class DERParser {
private:
    const std::vector<uint8_t>& data;
    size_t pos;

    void readSequence();
    void readObject();
    void readBitString();
    void readInteger();
    void readNull();

    uint8_t readTag();
    size_t readLength();

    BigInt readIntegerAsBigInt();

public:
    //DERParser() {};
    DERParser(const std::vector<uint8_t>& data) 
        : data(data), pos(0) {}

    void printDerAtPosition(); // For DEBUGGING
    //void decodeDER();
    RSAPublicKey decodeRSAKeyFromDER();
};