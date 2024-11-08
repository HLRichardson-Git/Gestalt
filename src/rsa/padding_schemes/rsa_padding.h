/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa_padding.h
 *
 */

# pragma once

#include "hash_utils/hash_utils.h"

const unsigned int SHA256_LENGTH = 32; // Hard coded hash len for sha2-256 for now

enum RSA_MGF_FUNCTIONS {
    MGF1
    //SHAKE128,
    //SHAKE256
};

std::string mgf1(const std::string& seed, unsigned int maskLen, HashAlgorithm hashAlg);