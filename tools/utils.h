#pragma once

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <thread>

std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr);
void hexStringToBytes(const std::string& hexString, unsigned char* output);
std::string convertToHex(const std::string input);
std::string generateRandomHexData(size_t numBytes);
std::string generateRandomData(size_t sizeInMB);
void xorBlock(unsigned char* a, std::string b, size_t blockIndex);