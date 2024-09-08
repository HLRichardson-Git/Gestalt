/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaObjects.h
 *
 */

# pragma once

#include <iostream>

#include "bigInt/bigInt.h"

enum class RSA_SECURITY_STRENGTH : unsigned int{
   RSA_1024 = 1024, // 80
   RSA_2048 = 2048, // 112
   RSA_3072 = 3072, // 128
   RSA_7680 = 7680, // 192
   RSA_15360 = 15360 // 256 
};

enum class ENCRYPTION_PADDING_SCHEME {
    NO_PADDING,
    PKCS1v15,
    OAEP
};

enum class SIGNATURE_PADDING_SCHEME {
    NO_PADDING,
    PKCS1v15,
    PSS
};