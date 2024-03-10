/*
 * utils.h
 *
 * This file contains utility functions used for various purposes such as converting between
 * hexadecimal strings and byte arrays, generating random data, and performing XOR operations
 * on byte arrays.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-03-10
 */

#pragma once

#include <vector>
#include <string>

std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr);
void hexStringToBytes(const std::string& hexString, unsigned char* output);
std::string convertToHex(const std::string input);
std::string generateRandomHexData(size_t numBytes);
std::string generateRandomData(size_t sizeInMB);
void xorBlock(unsigned char* a, std::string b, size_t blockIndex);