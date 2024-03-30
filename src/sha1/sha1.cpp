/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha1.cpp
 *
 * This file contains the implementation of Gestalts SHA1 security functions.
 */

#include <gestalt/sha1.h>
#include "sha1Core.h"

std::string hashSHA1(const std::string& in) {
    SHA1 SHA1object;
    return SHA1object.hash(in);
}