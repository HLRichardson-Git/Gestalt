#pragma once

#include <vector>
#include <string>
#include <random>
#include <thread>

std::vector<unsigned char> hexStringToBytesVec(const std::string& hexStr);
std::vector<unsigned char> generateRandomHexData(size_t numBytes);
std::vector<unsigned char> generateRandomData(size_t sizeInMB);
void xorBlock(std::vector<unsigned char>& a, std::vector<unsigned char>& b, size_t blockIndex);