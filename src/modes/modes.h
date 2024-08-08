/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * modes.h
 *
 * This header file defines functions for various block cipher modes such as ECB and CBC.
 * It includes function templates for encryption and decryption functions for these modes.
 */

#pragma once

#include <iostream> //debug
#include "aes/aesCore.h" //debug
#include <string>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

inline std::string toHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

inline std::string fromHex(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even length");
    }

    std::string binary;
    binary.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        binary.push_back(byte);
    }

    return binary;
}

/*template<typename BlockCipher, typename BlockType>
using function = void (BlockCipher::*)(BlockType*);

template<
    typename BlockCipher, 
    typename BlockType, 
    size_t BlockSize, 
    void (BlockCipher::*encryptBlock)(BlockType&), 
    std::string(*PaddingFunc)(const std::string&), 
    std::vector<BlockType>(*convertToBlocks)(const std::string&), 
    std::string(*blocksToHexString)(const std::vector<BlockType>&)
>
std::string encryptECB(std::string& msg, std::string key);

template<
    typename BlockCipher, 
    typename BlockType, 
    size_t BlockSize, 
    void (BlockCipher::*decryptBlock)(BlockType&), 
    std::string(*paddingFunc)(const std::string&), 
    std::vector<BlockType>(*convertToBlocks)(const std::string&), 
    std::string(*blocksToByteString)(const std::vector<BlockType>&)
>
std::string decryptECB(std::string& hexMsg, std::string key);*/

//template<typename BlockCipher, typename BlockType, size_t BlockSize, void(*PaddingFunc)(BlockType*, size_t, size_t)>
//std::string encryptCBC(std::string& msg, std::string key, std::string iv, function<BlockCipher, BlockType> encryptBlock);
//template<typename BlockCipher, typename BlockType, size_t BlockSize, void(*PaddingFunc)(BlockType*, size_t, size_t)>
//std::string decryptCBC(std::string& hexMsg, std::string key, std::string iv, function<BlockCipher, BlockType> decryptBlock);