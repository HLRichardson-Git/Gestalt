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
#include <cstring>
#include <iostream>

#include <gestalt/aes.h>
#include "aesCore.h"
#include "utils.h"

/*
 * Encrypts and arbitrarily input with AES_ECB.
 *
 * @param string The ASCII message to be encrypted.
 * @param string The 128, 192, or 256 bit key in hex.
 * @result Encrypted string in hex.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
std::string encryptAESECB(const std::string& msg, std::string key) {
    AES cipher(key);

    std::string paddedMsg = applyPKCS7Padding(msg);
    size_t paddedMsgLen = paddedMsg.length();

    unsigned char* input = new unsigned char[paddedMsgLen];
    memcpy(input, paddedMsg.c_str(), paddedMsgLen);

    for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += AES_BLOCK_SIZE) {
        cipher.encryptBlock(input + blockIndex);
    }

    std::string hexResult = toHex(reinterpret_cast<const unsigned char*>(input), paddedMsgLen);

    delete[] input;
    return hexResult;
}

/*
 * Decrypts and arbitrarily input with AES_ECB.
 *
 * @param string The encrypted hexidecimal value to be decrypted.
 * @param string The 128, 192, or 256 bit key in hex.
 * @result Decrypted string in ASCII.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
std::string decryptAESECB(const std::string& hexMsg, std::string key) {
    AES cipher(key);

    std::string msg = fromHex(hexMsg);
	size_t msgLen = msg.length();

	unsigned char* input = new unsigned char[msgLen];
	memcpy(input, msg.c_str(), msgLen);

	for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += AES_BLOCK_SIZE) {
		cipher.decryptBlock(input + blockIndex);
	}

    msg.assign(reinterpret_cast<char*>(input), msgLen);

	delete[] input;
    return removePKCS7Padding(msg);
}

/*
 * Encrypts and arbitrarily input with AES_CBC.
 *
 * @param string The ASCII message to be encrypted.
 * @param string The number-used-once (nonce) in hex.
 * @param string The 128, 192, or 256 bit key in hex.
 * @result Encrypted string in hex.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
std::string encryptAESCBC(const std::string& msg, std::string iv, std::string key) {
    AES cipher(key);

    std::string paddedMsg = applyPKCS7Padding(msg);
    size_t paddedMsgLen = paddedMsg.length();

    unsigned char* input = new unsigned char[paddedMsgLen];
    memcpy(input, paddedMsg.c_str(), paddedMsgLen);
	
	for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += AES_BLOCK_SIZE) {
		xorBlock(input, iv, blockIndex);
		cipher.encryptBlock(input + blockIndex);
		iv.assign(reinterpret_cast<char*>(input + blockIndex), AES_BLOCK_SIZE);
		iv = convertToHex(iv);
	}

	std::string hexResult = toHex(reinterpret_cast<const unsigned char*>(input), paddedMsgLen);

	delete[] input;
	return hexResult;
}

/*
 * Decrypts and arbitrarily input with AES_CBC.
 *
 * @param string The encrypted hexidecimal value to be decrypted.
 * @param string The number-used-once (nonce) in hex.
 * @param string The 128, 192, or 256 bit key in hex.
 * @result Decrypted string in ASCII.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
std::string decryptAESCBC(const std::string& hexMsg, std::string iv, std::string key) {
    AES cipher(key);

    std::string msg = fromHex(hexMsg);
	size_t msgLen = msg.length();

	unsigned char* input = new unsigned char[msgLen];
	memcpy(input, msg.c_str(), msgLen);

	std::string tmp = "";

	for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += AES_BLOCK_SIZE) {
		tmp.assign(reinterpret_cast<char*>(input + blockIndex), AES_BLOCK_SIZE);
		tmp = convertToHex(tmp);
		cipher.decryptBlock(input + blockIndex);
		xorBlock(input, iv, blockIndex);
		iv = tmp;
	}

	msg.assign(reinterpret_cast<char*>(input), msgLen);

	delete[] input;
    return removePKCS7Padding(msg);   
}