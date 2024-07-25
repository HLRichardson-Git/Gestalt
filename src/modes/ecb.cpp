/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecb.cpp
 *
 * This file contains the implementation of ECB (Electronic Codebook) mode encryption and decryption functions.
 * It includes functions to encrypt and decrypt data using ECB mode with various block ciphers.
 * 
 * References:
 * - NIST Special Publication SP800-38A: "Recommendation for Block Cipher Modes of Operation" (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 */

#include "modes.h"
#include <iomanip>
#include <iostream> // for debugging
#include <sstream>

#include "../../tools/utils.h"
#include "../aes/aesCore.h"
#include <gestalt/des.h>

/*
 * Electronic Codebook (ECB) Encryption In-Place:
 * 
 * The Electronic Codebook (ECB) mode is a confidentiality mode that features, for a given key,
 * the assignment of a fixed ciphertext block to each plaintext block, analogous to the assignment of
 * code words in a codebook.
 *
 * ECB Encryption: msg = encryptBlock(msg + blockIndex) blockIndex = 0, 16, ..., n
 *
 * In ECB encryption, the forward cipher function is applied directly and independently to each
 * block of the plaintext. The resulting sequence of output blocks is the ciphertext.
 *
 * ECB Encryption:
 *   Input:  Plaintext msg, key K
 *   Output: Ciphertext msg
 *
 * In ECB encryption, multiple forward cipher functions can be computed in parallel.
 */
template<typename BlockCipher, typename BlockType, size_t BlockSize, void(*PaddingFunc)(BlockType*, size_t, size_t)>
std::string encryptECB(std::string& msg, std::string key, function<BlockCipher, BlockType> encryptBlock) {
    size_t msgLen = msg.length();
    size_t paddedMsgLen = msgLen + BlockSize - (msgLen % BlockSize);

    BlockType* input = new BlockType[paddedMsgLen];
    memcpy(input, msg.c_str(), msgLen);

    PaddingFunc(input, msgLen, paddedMsgLen);

    BlockCipher cipher(key);

    for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += BlockSize) {
        (cipher.*encryptBlock)(input + blockIndex);
    }

    std::string hexResult = toHex(reinterpret_cast<const unsigned char*>(input), paddedMsgLen);

    delete[] input;
    return hexResult;
}

/*
 * Electronic Codebook (ECB) Decryption In-Place:
 * 
 * The Electronic Codebook (ECB) mode is a confidentiality mode that features, for a given key,
 * the assignment of a fixed ciphertext block to each plaintext block, analogous to the assignment of
 * code words in a codebook.
 *
 * ECB Decryption: msg = decryptBlock(msg + blockIndex) for blockIndex = 0, 16, ..., n.
 *
 * In ECB decryption, the inverse cipher function is applied directly and independently to each
 * block of the ciphertext. The resulting sequence of output blocks is the plaintext.
 *
 * ECB Decryption:
 *   Input:  Ciphertext msg, key K
 *   Output: Plaintext msg
 *
 * In ECB decryption, multiple inverse cipher functions can be computed in parallel.
 */
template<typename BlockCipher, typename BlockType, size_t BlockSize, void(*PaddingFunc)(BlockType*, size_t, size_t)>
std::string decryptECB(std::string& hexMsg, std::string key, function<BlockCipher, BlockType> decryptBlock) {\
    std::string msg = fromHex(hexMsg);

	size_t msgLen = msg.length();

	BlockType* input = new BlockType[msgLen];
	memcpy(input, msg.c_str(), msgLen);

    BlockCipher cipher(key);

	for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += BlockSize) {
		(cipher.*decryptBlock)(input + blockIndex);
	}

	size_t origMsgLen = msgLen - static_cast<size_t>(input[msgLen - 1]);
	PaddingFunc(input, origMsgLen, msgLen);

	msg.assign(reinterpret_cast<char*>(input), origMsgLen);

	delete[] input;
    return msg;
}

template std::string encryptECB<AES, unsigned char, 16, applyPCKS7Padding>(std::string&, std::string, function<AES, unsigned char>);
template std::string decryptECB<AES, unsigned char, 16, removePCKS7Padding>(std::string&, std::string, function<AES, unsigned char>);

//template std::string encryptECB<DES, uint64_t, 8, applyPKCS5Padding>(std::string&, std::string, function<DES, uint64_t>);