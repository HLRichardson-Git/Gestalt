/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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
    return HMAC(SHA224).keyedHash(key, input, [](const std::string& in) { return hashSHA224(SecureBytes::fromAscii(in)).toHex(); });
}

inline std::string hmacSHA256(const std::string& key, const std::string& input) {
    return HMAC(SHA256).keyedHash(key, input, [](const std::string& in) { return hashSHA256(SecureBytes::fromAscii(in)).toHex(); });
}

inline std::string hmacSHA384(const std::string& key, const std::string& input) {
    return HMAC(SHA384).keyedHash(key, input, [](const std::string& in) { return hashSHA384(SecureBytes::fromAscii(in)).toHex(); });
}

inline std::string hmacSHA512(const std::string& key, const std::string& input) {
    return HMAC(SHA512).keyedHash(key, input, [](const std::string& in) { return hashSHA512(SecureBytes::fromAscii(in)).toHex(); });
}

inline std::string hmacSHA512_224(const std::string& key, const std::string& input) {
    return HMAC(SHA512_224).keyedHash(key, input, [](const std::string& in) { return hashSHA512_224(SecureBytes::fromAscii(in)).toHex(); });
}

inline std::string hmacSHA512_256(const std::string& key, const std::string& input) {
    return HMAC(SHA512_256).keyedHash(key, input, [](const std::string& in) { return hashSHA512_256(SecureBytes::fromAscii(in)).toHex(); });
}