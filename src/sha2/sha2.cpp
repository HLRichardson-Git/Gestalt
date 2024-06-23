/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2.cpp
 *
 * This file contains the implementation of Gestalts SHA2 security functions.
 */

#include <gestalt/sha2.h>
#include "sha2Core.h"

std::string hashSHA2(std::string& in) {
    return hashSHA2TEMP(in);
}