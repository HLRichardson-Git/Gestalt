/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hmac.h
 *
 * This file contains the definitions of Gestalts HMAC security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>
#include <cstdint>

typedef SecureBytes (*hash_f)(const SecureBytes& in);

enum HASH_ALGORITHM { SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256 };

class HMAC {
private:
    uint64_t B;
    uint64_t L;

    SecureBytes ipad;
    SecureBytes opad;
    SecureBytes K;

    static std::pair<unsigned int, unsigned int> getHashParameters(const HASH_ALGORITHM HASH);
    void hmacManager(const HASH_ALGORITHM HASH);
    void processKey(const SecureBytes& key, hash_f hash);
    SecureBytes xorVectors(const SecureBytes& a, const SecureBytes& b);

public:

    explicit HMAC (HASH_ALGORITHM HASH) {
        hmacManager(HASH);
        ipad = SecureBytes(B, 0x36);
        opad = SecureBytes(B, 0x5c);
        K    = SecureBytes(B, 0x00);
    }

    SecureBytes keyedHash(const SecureBytes& key, const SecureBytes& input, hash_f hash);
};