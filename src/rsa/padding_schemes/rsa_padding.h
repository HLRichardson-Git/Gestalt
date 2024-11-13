/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa_padding.h
 *
 * This file implements the Mask Generation Function (MGF1), which generates a mask of a specified length based on a 
 * given seed and hash algorithm (such as SHA1, SHA256, etc.). The MGF1 function is commonly used in cryptographic 
 * protocols like RSA-PSS and OAEP.
 * 
 */

# pragma once

#include "hash_utils/hash_utils.h"

class OAEPParams;
class PSSParams;

enum RSA_MGFFunctions {
    MGF1
    // TODO: Allow these when these are implemented.
    //SHAKE128,
    //SHAKE256
};

std::string mgf1(const std::string& seed, unsigned int maskLen, HashAlgorithm hashAlg);