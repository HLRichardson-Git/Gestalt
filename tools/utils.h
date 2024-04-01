/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
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

std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr);
void hexStringToBytes(const std::string& hexString, unsigned char* output);
std::string convertToHex(const std::string& input);
std::string DecimalToBinary(int num);
int hexStringToInt(const std::string& hexString);
std::string generateRandomHexData(size_t numBytes);
std::string generateRandomData(size_t sizeInMB);
void xorBlock(unsigned char* a, const std::string& b, size_t blockIndex);