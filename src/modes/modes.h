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
#include "../aes/aes.h"

#include <string>

template<typename BlockCipher>
using function = void (BlockCipher::*)(unsigned char*);

template<typename BlockCipher>
void encrypt_ecb(std::string& msg, std::string key, function<BlockCipher> encryptBlock);
template<typename BlockCipher>
void decrypt_ecb(std::string& msg, std::string key, function<BlockCipher> decryptBlock);

template<typename BlockCipher>
void encrypt_cbc(std::string& msg, std::string key, std::string iv, function<BlockCipher> encryptBlock);
template<typename BlockCipher>
void decrypt_cbc(std::string& msg, std::string key, std::string iv, function<BlockCipher> decryptBlock);