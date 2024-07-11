/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hmac.cpp
 *
 * This file contains the implementation of Gestalts HMAC security functions.
 */

#include <iostream>
#include <iomanip> // can delete after debugging
//#include <bits/stdc++.h>
#include <sstream>
#include <algorithm>

#include "hmac.h"
#include "utils.h" // can delete after debugging

std::string hexToASCII(std::string hex)
{
    //std::cout << "INPUT:  " << hex << std::endl;
    std::string res;
    res.reserve(hex.size() / 2);
    for (int i = 0; i < hex.size(); i += 2)
    {
        std::istringstream iss(hex.substr(i, 2));
        int temp;
        iss >> std::hex >> temp;
        res += static_cast<char>(temp);
    }
    return res;
}

void HMAC::printHex(const std::vector<unsigned char>& vec) {
    for (const auto& byte : vec) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

void HMAC::hmacManager(const HASH_ALGORITHM HASH) {
    switch (HASH) {
    case SHA1:
        B = 64;
        L = 20;
        break;
    case SHA224:
        B = 64;
        L = 28;
        break;
    case SHA256:
        B = 64;
        L = 32;
        break;
    case SHA384:
        B = 128;
        L = 48;
        break;
    case SHA512:
        B = 128;
        L = 64;
        break;
    case SHA512_224:
        B = 128;
        L = 28;
        break;
    case SHA512_384:
        B = 128;
        L = 32;
        break;
    default:
        B = 0;
        L = 0;
        std::cout << "Error: Invalid hash algorithm given" << std::endl;
        break;
    }

    //std::vector<unsigned char> temp_ipad(B, 0x36);
    //std::vector<unsigned char> temp_opad(B, 0x5c);

    //std::copy(temp_ipad.begin(), temp_ipad.end(), ipad.begin());
    //std::copy(temp_opad.begin(), temp_opad.end(), opad.begin());
}

void HMAC::processKey(const std::string& key, hash_f hash) {
    size_t keySize = key.length();
    std::vector<unsigned char> subKey(B, 0x00); // vector of length B intitialized with 0's

    if (keySize > B) {
        std::string hashedKey = hash(key);
        std::copy(hashedKey.begin(), hashedKey.end(), subKey.begin());
    } else {
        std::copy(key.begin(), key.end(), subKey.begin());
    }
    
    //std::copy(subKey.begin(), subKey.end(), K.begin());
    K = subKey;
    //std::cout << "KEY = ";
    //printHex(K);
}

std::string HMAC::xorVectors(std::vector<unsigned char> a, std::vector<unsigned char> b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Vectors must be of the same length");
    }

    std::string result;
    result.reserve(a.size()); // Reserve space for the result

    for (size_t i = 0; i < a.size(); ++i) {
        result.push_back(a[i] ^ b[i]);
    }
    //std::cout << "reult after xor: " << convertToHex(result) << std::endl;
    return result;
}

std::string HMAC::keyedHash(const std::string& key, const std::string& input, hash_f hash) {
    processKey(key, hash);
    //return hash((xorVectors(K, opad)) + (hash(xorVectors(K, ipad) + input)));
    std::string inner = xorVectors(K, ipad) + input;
    //std::cout << "reult after xor + input: " << convertToHex(inner) << std::endl;
    std::string innerHash = hash(inner);
    //std::cout << "reult after innerhash: " << innerHash << std::endl;
    //std::string outer = xorVectors(K, opad) + innerHash;
    std::string outer = xorVectors(K, opad) + hexToASCII(innerHash);
    //std::cout << "reult after xor + innerhash: " << convertToHex(xorVectors(K, opad)) + innerHash << std::endl;
    //std::cout << "reult ascii: " << hexToASCII(outer) << std::endl;
    //std::cout << "reult after outerhash: " << hash(outer) << std::endl;
    return hash(outer);
}