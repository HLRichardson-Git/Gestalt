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

#include <string>
#include <cstring>

template<typename BlockCipher>
using function = void (BlockCipher::*)(unsigned char*);

template<typename BlockCipher>
std::string encryptECB(std::string& msg, std::string key, function<BlockCipher> encryptBlock);
template<typename BlockCipher>
std::string decryptECB(std::string& msg, std::string key, function<BlockCipher> decryptBlock);

template<typename BlockCipher>
std::string encryptCBC(std::string& msg, std::string key, std::string iv, function<BlockCipher> encryptBlock);
template<typename BlockCipher>
std::string decryptCBC(std::string& msg, std::string key, std::string iv, function<BlockCipher> decryptBlock);