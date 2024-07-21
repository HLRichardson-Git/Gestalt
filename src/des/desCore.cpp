/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * desCore.cpp
 *
 * This file contains the implementation of Gestalts DES security functions.
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <bitset>
#include <sstream>

#include "desCore.h"
#include "desConstants.h"

uint64_t DES::permute(uint64_t input, const int* table, int inputSize, int outputSize) {
    uint64_t output = 0;
    for (int i = 0; i < outputSize; ++i) {
        output <<= 1;
        output |= (input >> (inputSize - table[i])) & 0x01;
    }
    return output;
}

uint32_t DES::permute(uint32_t input, const int* table, int inputSize, int outputSize) {
    uint32_t output = 0;
    for (int i = 0; i < outputSize; ++i) {
        output <<= 1;
        output |= (input >> (inputSize - table[i])) & 0x01;
    }
    return output;
}

uint32_t DES::leftRotate(uint32_t key, int shifts) {
    return ((key << shifts) & 0x0FFFFFFF) | (key >> (28 - shifts));
}

void DES::generateRoundKeys(const std::string& binaryKey) {
    uint64_t key = std::bitset<64>(binaryKey).to_ullong();
    uint64_t permutedKey = permute(key, PC1, 64, PC1_SIZE);

    uint32_t left = (permutedKey >> 28) & 0xFFFFFFF;
    uint32_t right = permutedKey & 0xFFFFFFF;

    for (int i = 0; i < 16; ++i) {
        left = leftRotate(left, keyShifts[i]);
        right = leftRotate(right, keyShifts[i]);

        uint64_t combinedKey = (static_cast<uint64_t>(left) << 28) | right;
        roundKeys[i] = permute(combinedKey, PC2, 56, PC2_SIZE);
    }
}

uint32_t DES::sboxSubstitution(uint64_t input) {
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t chunk = (input >> (42 - 6 * i)) & 0x3F;
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F; 
        output <<= 4;
        output |= SBOX[i][row][col];
    }
    return output;
}

uint32_t DES::f(uint32_t rightChunk, size_t round) {
    uint64_t expandedChunk = permute(static_cast<uint64_t>(rightChunk), E, 32, E_SIZE) & 0x0000FFFFFFFFFFFF;
    return permute(sboxSubstitution(expandedChunk ^ roundKeys[round]), P, 32, P_SIZE);
}  

/*uint64_t DES::encryptBlock(uint64_t block) {
    block = permute(block, IP, DES_BLOCK_SIZE, IP_SIZE); // Initial permutation

    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    for (size_t round = 0; round < DES_NUM_OF_ROUNDS - 1; round++) {
        uint32_t temp = left ^ f(right, round);

        left = right;
        right = temp;
    }

    // Final round without swapping halves
    left ^= f(right, DES_NUM_OF_ROUNDS - 1);
    block = (static_cast<uint64_t>(left) << 32) | right;

    return permute(block, FP, DES_BLOCK_SIZE, FP_SIZE); // Final permutation
}*/

uint64_t DES::encryptBlock(uint64_t block) {
    block = permute(block, IP, DES_BLOCK_SIZE, IP_SIZE); // Initial permutation

    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    for (size_t round = 0; round < DES_NUM_OF_ROUNDS - 1; round++) {
        uint32_t temp = left ^ f(right, round);

        left = right;
        right = temp;
    }

    // Final round without swapping halves
    left ^= f(right, DES_NUM_OF_ROUNDS - 1);
    block = (static_cast<uint64_t>(left) << 32) | right;

    return permute(block, FP, DES_BLOCK_SIZE, FP_SIZE); // Final permutation
}

uint64_t DES::decryptBlock(uint64_t block) {
    block = permute(block, IP, DES_BLOCK_SIZE, IP_SIZE); // Initial permutation

    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    for (size_t round = DES_NUM_OF_ROUNDS - 1; round > 0; --round) {
        uint32_t temp = left ^ f(right, round);

        left = right;
        right = temp;
    }

    // Final round without swapping halves
    left ^= f(right, 0);
    block = (static_cast<uint64_t>(left) << 32) | right;

    return permute(block, FP, DES_BLOCK_SIZE, FP_SIZE); // Final permutation
}

/*void applyPKCS5Padding(uint64_t* input, size_t msgLen, size_t paddedLen) {
    unsigned char paddingValue = paddedLen - msgLen;
    for (size_t i = msgLen; i < paddedLen; ++i) {
        reinterpret_cast<unsigned char*>(input)[i] = paddingValue;
    }
}
void applyPKCS5Padding(uint64_t* input, size_t msgLen, size_t paddedLen) {
    // Calculate the number of elements in the last block
    int elementsInLastBlock = 8 - (msgLen % 8);
    unsigned char paddingValue = static_cast<unsigned char>(elementsInLastBlock);
    // Pad the message with the padding value
    for (size_t i = msgLen; i < paddedLen; i++) {
        input[i] = paddingValue;
    }
}

std::string desEncryptECB(std::string& msg, const std::string& key) {
    return encryptECB<DES, uint64_t, 8, applyPKCS5Padding>(msg, key, &DES::encryptBlock);
}*/

std::string applyPCKS5Padding(const std::string& data) {
    size_t blockSize = 8;
    size_t paddingLength = blockSize - (data.size() % blockSize);
    std::string paddedData = data;
    paddedData.append(paddingLength, static_cast<char>(paddingLength));
    return paddedData;
}

std::string removePKCS5Padding(const std::string& data) {
    if (data.empty()) {
        throw std::runtime_error("Data is empty, cannot remove padding.");
    }
    size_t paddingLength = static_cast<uint8_t>(data.back());
    if (paddingLength > data.size() || paddingLength > 8) {
        throw std::runtime_error("Invalid padding length.");
    }
    return data.substr(0, data.size() - paddingLength);
}

uint64_t hexStringToUint64(const std::string& hexStr) {
    if (hexStr.length() != 16) {
        throw std::invalid_argument("Hex string must be 16 characters long");
    }
    
    uint64_t result = 0;
    std::stringstream ss;
    ss << std::hex << hexStr;
    ss >> result;
    
    if (ss.fail()) {
        throw std::invalid_argument("Invalid hex string");
    }
    
    return result;
}

std::vector<uint64_t> stringToBlocks(const std::string& str) {
    std::vector<uint64_t> blocks;
    for (size_t i = 0; i < str.size(); i += 8) {
        uint64_t block = 0;
        for (size_t j = 0; j < 8 && i + j < str.size(); ++j) {
            block <<= 8;
            block |= static_cast<uint8_t>(str[i + j]);
        }
        blocks.push_back(block);
    }
    return blocks;
}

std::vector<uint64_t> hexStringToBlocks(const std::string& hex) {
    std::vector<uint64_t> blocks;
    for (size_t i = 0; i < hex.size(); i += 16) {
        uint64_t block = 0;
        for (size_t j = 0; j < 16 && i + j < hex.size(); ++j) {
            block <<= 4;
            char hexChar = hex[i + j];
            if (hexChar >= '0' && hexChar <= '9') {
                block |= (hexChar - '0');
            } else if (hexChar >= 'A' && hexChar <= 'F') {
                block |= (hexChar - 'A' + 10);
            } else if (hexChar >= 'a' && hexChar <= 'f') {
                block |= (hexChar - 'a' + 10);
            } else {
                throw std::runtime_error("Invalid hex character.");
            }
        }
        blocks.push_back(block);
    }
    return blocks;
}

std::string blocksToHexString(const std::vector<uint64_t>& blocks) {
    std::ostringstream oss;
    for (uint64_t block : blocks) {
        oss << std::hex << std::setw(16) << std::setfill('0') << block;
    }
    return oss.str();
}

std::string blocksToString(const std::vector<uint64_t>& blocks) {
    std::string str;
    for (uint64_t block : blocks) {
        for (int i = 7; i >= 0; --i) {
            str += static_cast<char>((block >> (i * 8)) & 0xFF);
        }
    }
    return str;
}