/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * cbc.cpp
 *
 * This file contains the implementation of cbc (Cipher Block Chaining) mode encryption and decryption functions.
 * It includes functions to encrypt and decrypt data using CBC mode with various block ciphers.
 * 
 * References:
 * - NIST Special Publication SP800-38A: "Recommendation for Block Cipher Modes of Operation" (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 */

#include <iostream>

#include "modes.h"

#include "../../tools/utils.h"
#include "../aes/aesCore.h"

/*
 * Cipher Block Chaining (CBC) Encryption In-Place:
 * 
 * The Cipher Block Chaining (CBC) mode is a confidentiality mode whose encryption process
 * features the combining (“chaining”) of the plaintext blocks with the previous ciphertext blocks.
 * The CBC mode requires an IV to combine with the first plaintext block.
 *
 * CBC Encryption:  msg = msg ⊕ iv.
 * 					msg = encryptBlock(msg  + blockIndex) for blockIndex = 0, 16, ..., n.
 * 					iv  = msg.
 *
 * In CBC encryption, the first input block is formed by exclusive-ORing the first block of the
 * plaintext with the IV. The forward cipher function is applied to the first input block, and the
 * resulting output block is the first block of the ciphertext. Each successive plaintext block is
 * exclusive-ORed with the previous ciphertext block to produce the new input block.
 * The forward cipher function is applied to each input block to produce the ciphertext block.
 *
 * CBC Encryption:
 *   Input:  Plaintext msg, key K, initialization vector IV
 *   Output: Ciphertext msg
 *
 * In CBC encryption, forward cipher operations cannot be performed in parallel.
 */
/*template<typename BlockCipher, typename BlockType, size_t BlockSize, void(*PaddingFunc)(BlockType*, size_t, size_t)>
std::string encryptCBC(std::string& msg, std::string key, std::string iv, function<BlockCipher, BlockType> encryptBlock) {
    size_t msgLen = msg.length();
	size_t paddedMsgLen = msgLen + BlockSize - (msgLen % BlockSize);

	BlockType* input = new BlockType[paddedMsgLen];
	memcpy(input, msg.c_str(), msgLen);

	PaddingFunc(input, msgLen, paddedMsgLen);

    BlockCipher cipher(key);
	
	for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += BlockSize) {
		xorBlock(input, iv, blockIndex);
		(cipher.*encryptBlock)(input + blockIndex);
		iv.assign(reinterpret_cast<char*>(input + blockIndex), BlockSize);
		iv = convertToHex(iv);
	}

	std::string hexResult = toHex(reinterpret_cast<const unsigned char*>(input), paddedMsgLen);

	delete[] input;
	return hexResult;
}*/

/*
 * Cipher Block Chaining (CBC) Decryption In-Place:
 * 
 * The Cipher Block Chaining (CBC) mode is a confidentiality mode whose encryption process
 * features the combining (“chaining”) of the plaintext blocks with the previous ciphertext blocks.
 * The CBC mode requires an IV to combine with the first plaintext block.
 *
 * CBC Decryption:  iv  = msg.
 * 				 	msg = decryptBlock(msg + blockIndex) ⊕ iv for blockIndex = 0, 16, ..., n.
 * 					msg = msg ⊕ iv.
 *
 * In CBC decryption, the inverse cipher function is applied to the first ciphertext block, and the
 * resulting output block is exclusive-ORed with the initialization vector to recover the first
 * plaintext block. Each successive ciphertext block is exclusive-ORed with the previous
 * ciphertext block to recover the plaintext block.
 *
 * CBC Decryption:
 *   Input:  Ciphertext msg, key K, initialization vector IV
 *   Output: Plaintext msg
 *
 * In CBC decryption, multiple inverse cipher operations can be performed in parallel.
 */

/*template<typename BlockCipher, typename BlockType, size_t BlockSize, void(*PaddingFunc)(BlockType*, size_t, size_t)>
std::string decryptCBC(std::string& hexMsg, std::string key, std::string iv, function<BlockCipher, BlockType> decryptBlock) {
	std::string msg = fromHex(hexMsg);

    size_t msgLen = msg.length();
	BlockType* input = new BlockType[msgLen];
	memcpy(input, msg.c_str(), msgLen);

	std::string tmp = "";

	// Create an instance of the block cipher with the provided key
    BlockCipher cipher(key);

	for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += BlockSize) {
		tmp.assign(reinterpret_cast<char*>(input + blockIndex), BlockSize);
		tmp = convertToHex(tmp);
		(cipher.*decryptBlock)(input + blockIndex);
		xorBlock(input, iv, blockIndex);
		iv = tmp;
	}

	size_t origMsgLen = msgLen - static_cast<size_t>(input[msgLen - 1]);
	PaddingFunc(input, origMsgLen, msgLen);

	msg.assign(reinterpret_cast<char*>(input), origMsgLen);

	delete[] input;
	return msg;
}*/

//template std::string encryptCBC<AES, unsigned char, 16, applyPCKS7Padding>(std::string&, std::string, std::string, function<AES, unsigned char>);
//template std::string decryptCBC<AES, unsigned char, 16, removePCKS7Padding>(std::string&, std::string, std::string, function<AES, unsigned char>);