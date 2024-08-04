/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aes.cpp
 *
 * This file contains the implementation of Gestalts AES security functions.
 */

#include <string>
#include <iostream>

#include <gestalt/aes.h>
#include "../aes/aesCore.h"
#include "../modes/modes.h"

std::string encryptAESECB(std::string msg, std::string key) {
    return encryptECB<
            AES, 
            aesBlock, 
            AES_BLOCK_SIZE,
            &AES::encryptBlock, 
            applyPKCS7Padding, 
            convertToAESBlocks, 
            aesBlocksToHexString
        >(msg, key);
}

std::string decryptAESECB(std::string msg, std::string key) {
    return decryptECB<
            AES, 
            aesBlock, 
            AES_BLOCK_SIZE, 
            &AES::decryptBlock, 
            removePKCS7Padding, 
            convertToAESBlocks, 
            aesBlocksToBytesString
        >(msg, key);
}

std::string encryptAESCBC(std::string msg, std::string iv, std::string key) {
	//return encryptCBC<AES, unsigned char, 16, applyPCKS7Padding>(msg, key, iv, &AES::encryptBlock);
    return "";
}

std::string decryptAESCBC(std::string msg, std::string iv, std::string key) {
	//return decryptCBC<AES, unsigned char, 16, removePKCS7Padding>(msg, key, iv, &AES::decryptBlock);
    return "";
}