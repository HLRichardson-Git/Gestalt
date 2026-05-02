/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * utils.h
 *
 * This file contains utility functions used for various purposes such as converting between
 * hexadecimal strings and byte arrays, generating random data, and performing XOR operations
 * on byte arrays.
 */

#pragma once

#include <vector>
#include <string>
#include <cstdint>

// Used for DER <-> PEM conversions
std::string base64Encode(const std::vector<uint8_t>& hexVector);
std::vector<uint8_t> base64Decode(const std::string& baseSixtyFourString);

std::string bytesToHex(const std::string& bytes);

std::string printIntToBinary(uint64_t in);
std::string printIntToBinary(uint32_t in);
