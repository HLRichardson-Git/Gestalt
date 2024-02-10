#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <thread>

std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr);
void hexStringToBytes(const std::string& hexString, unsigned char* output);
std::vector<unsigned char> generateRandomHexData(size_t numBytes);
std::string generateRandomData(size_t sizeInMB);
void xorBlock(unsigned char* a, const unsigned char* b, size_t blockIndex);