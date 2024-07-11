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

std::string hmac_sha256(const std::string& key, const std::string& input) {
    return HMAC(SHA256).keyedHash(key, input, hashSHA256);
}