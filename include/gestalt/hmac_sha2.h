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

std::string hmac_sha224(const std::string& key, const std::string& input) {
    return HMAC(SHA224).keyedHash(key, input, hashSHA224);
}

std::string hmac_sha256(const std::string& key, const std::string& input) {
    return HMAC(SHA256).keyedHash(key, input, hashSHA256);
}

std::string hmac_sha384(const std::string& key, const std::string& input) {
    return HMAC(SHA384).keyedHash(key, input, hashSHA384);
}

std::string hmac_sha512(const std::string& key, const std::string& input) {
    return HMAC(SHA512).keyedHash(key, input, hashSHA512);
}

std::string hmac_sha512_224(const std::string& key, const std::string& input) {
    return HMAC(SHA512_224).keyedHash(key, input, hashSHA512_224);
}

std::string hmac_sha512_256(const std::string& key, const std::string& input) {
    return HMAC(SHA512_256).keyedHash(key, input, hashSHA512_256);
}