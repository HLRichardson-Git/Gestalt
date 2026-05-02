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

inline SecureBytes hmacSHA224(const SecureBytes& key, const SecureBytes& input) {
    return HMAC(SHA224).keyedHash(key, input, hashSHA224);
}

inline SecureBytes hmacSHA256(const SecureBytes& key, const SecureBytes& input) {
    return HMAC(SHA256).keyedHash(key, input, hashSHA256);
}

inline SecureBytes hmacSHA384(const SecureBytes& key, const SecureBytes& input) {
    return HMAC(SHA384).keyedHash(key, input, hashSHA384);
}

inline SecureBytes hmacSHA512(const SecureBytes& key, const SecureBytes& input) {
    return HMAC(SHA512).keyedHash(key, input, hashSHA512);
}

inline SecureBytes hmacSHA512_224(const SecureBytes& key, const SecureBytes& input) {
    return HMAC(SHA512_224).keyedHash(key, input, hashSHA512_224);
}

inline SecureBytes hmacSHA512_256(const SecureBytes& key, const SecureBytes& input) {
    return HMAC(SHA512_256).keyedHash(key, input, hashSHA512_256);
}