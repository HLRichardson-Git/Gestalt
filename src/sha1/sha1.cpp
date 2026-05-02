/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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

SecureBytes hashSHA1(const SecureBytes& in) {
    SHA1 SHA1object;
    return SHA1object.hash(in);
}