/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2.h
 *
 * This file contains the definitions of Gestalts SHA2 security functions.
 */

#pragma once

#include <gestalt/sha2.h>
#include "hmac/hmac.h"

inline std::string hmacSHA224(const std::string& key, const std::string& input) {
    return HMAC(SHA224).keyedHash(key, input, hashSHA224);
}

inline std::string hmacSHA256(const std::string& key, const std::string& input) {
    return HMAC(SHA256).keyedHash(key, input, hashSHA256);
}

inline std::string hmacSHA384(const std::string& key, const std::string& input) {
    return HMAC(SHA384).keyedHash(key, input, hashSHA384);
}

inline std::string hmacSHA512(const std::string& key, const std::string& input) {
    return HMAC(SHA512).keyedHash(key, input, hashSHA512);
}

inline std::string hmacSHA512_224(const std::string& key, const std::string& input) {
    return HMAC(SHA512_224).keyedHash(key, input, hashSHA512_224);
}

inline std::string hmacSHA512_256(const std::string& key, const std::string& input) {
    return HMAC(SHA512_256).keyedHash(key, input, hashSHA512_256);
}