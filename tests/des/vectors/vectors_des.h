/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_des.cpp
 *
 * This file contains the vectors used to test DES.
 */

#pragma once

#include <gestalt/secure_bytes.h>

const SecureBytes key  = SecureBytes::fromHex("752878397493CB70");
const SecureBytes key2 = SecureBytes::fromHex("10316E028C8F3B4A");
const SecureBytes key3 = SecureBytes::fromHex("7CA110454A1A6E57");
const SecureBytes nonce = SecureBytes::fromHex("0102030405060708");
const SecureBytes plaintext = SecureBytes::fromAscii("Hello, Gestalt!");
const SecureBytes multiBlockPT = SecureBytes::fromAscii(
    "In the spring of her twenty-second year, Sumire fell in love for the first time in her life. An intense love, "
    "a veritable tornado sweeping across the plains flattening everything in its path, tossing things up in the air, "
    "ripping them to shreds, crushing them to bits.");