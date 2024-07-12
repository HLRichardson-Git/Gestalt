/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hmac.h
 *
 * This file contains the definitions of Gestalts HMAC security functions.
 */

#pragma once

#include <string>
#include <vector>

typedef std::string (*hash_f)(const std::string& in);

enum HASH_ALGORITHM { SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256 };

class HMAC {
private:
    uint64_t B;
    uint64_t L;
    
    std::vector<unsigned char> ipad;
    std::vector<unsigned char> opad;
    std::vector<unsigned char> K;     
    
    static std::pair<unsigned int, unsigned int> getHashParameters(const HASH_ALGORITHM HASH);
    void hmacManager(const HASH_ALGORITHM HASH);
    void processKey(const std::string& key, hash_f hash);
    std::string xorVectors(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b);

public:

    explicit HMAC (HASH_ALGORITHM HASH) { 
        hmacManager(HASH); 
        ipad = std::vector<unsigned char>(B, 0x36);
        opad = std::vector<unsigned char>(B, 0x5c);
        K    = std::vector<unsigned char>(B, 0x00);
    }

    std::string keyedHash(const std::string& key, const std::string& input, hash_f hash);
};