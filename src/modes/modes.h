/*
 * modes.h
 *
 * This header file defines functions for various block cipher modes such as ECB and CBC.
 * It includes function templates for encryption and decryption functions for these modes.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-02-24
 */

#pragma once

#include "../../tools/utils.h"
#include "../aes/aesCore.h"

#include <string>
#include <cstring>

template<typename BlockCipher>
using function = void (BlockCipher::*)(unsigned char*);

template<typename BlockCipher>
std::string encrypt_ecb(std::string& msg, std::string key, function<BlockCipher> encryptBlock);
template<typename BlockCipher>
std::string decrypt_ecb(std::string& msg, std::string key, function<BlockCipher> decryptBlock);

template<typename BlockCipher>
std::string encrypt_cbc(std::string& msg, std::string key, std::string iv, function<BlockCipher> encryptBlock);
template<typename BlockCipher>
std::string decrypt_cbc(std::string& msg, std::string key, std::string iv, function<BlockCipher> decryptBlock);