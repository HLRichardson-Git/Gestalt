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

/*
 * TODO: these following 9 functions was my first attempt to streamline parsing user inputs.
 *       I still want to explore better ideas as this one tried to use the input to determine the format
 *       but this ran into issues (e.g. a valid byte string is 1234, but would be treated as hex with this).
 *       The best idea I have right now is to expect users to prepend values to inputs (e.g. 0x1234 for hex)
 */
std::string hexToBytes(const std::string& hex);
std::string hexToBits(const std::string& hex);
std::string bytesToHex(const std::string& bytes);
std::string bytesToBits(const std::string& bytes);
std::string bitsToBytes(const std::string& bits);
std::string bitsToHex(const std::string& bits);
std::string convertToBytes(const std::string& input);
std::string convertToHex(const std::string& input);
std::string convertToBits(const std::string& input);

bool isHex(std::string in);
std::string trimHexStr(const std::string& hex);
//std::string hexToBytes(std::string hex); 
std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr);
void hexStringToBytes(const std::string& hexString, unsigned char* output);
//std::string convertToHex(const std::string& input);
std::string decimalToBinary(int num);
int hexStringToInt(const std::string& hexString);
std::string hexToBinary(const std::string& hexStr);
std::string generateRandomHexData(size_t numBytes);
std::string generateRandomData(size_t sizeInMB);
void xorBlock(unsigned char* a, const std::string& b, size_t blockIndex);
std::string printIntToBinary(uint64_t in);
std::string printIntToBinary(uint32_t in);
std::string toHex(const unsigned char* data, size_t length);
std::string fromHex(const std::string& hex);
unsigned int xorHexStrings(const std::string& hexStr1, const std::string& hexStr2);