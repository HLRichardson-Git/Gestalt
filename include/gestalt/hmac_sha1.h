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

#include <gestalt/sha1.h>
#include "hmac/hmac.h"

std::string hmacSHA1(const std::string& key, const std::string& input) {
    return HMAC(SHA1).keyedHash(key, input, hashSHA1);
}