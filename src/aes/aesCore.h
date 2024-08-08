/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aesCore.h
 *
 * This file contains an implementation of the Advanced Encryption Standard (AES) algorithm in C++.
 * AES is a symmetric encryption algorithm widely used for securing sensitive data.
 * This implementation supports AES-128, AES-192, and AES-256 encryption and decryption.
 *
 * The implementation follows the AES specification, and the key expansion is performed according
 * to the AES key schedule algorithm.
 *
 * The encryption and decryption functions work on individual 128-bit blocks of data.
 * For messages longer than one block, developers should use a mode of operation such as 
 * CBC (Cipher Block Chaining), or CTR (Counter Mode), etc to achieve secure
 * encryption of the entire message.
 *
 * This implementation is designed to be portable and easy to use, providing a straightforward
 * interface for encrypting and decrypting data using AES.
 */

#pragma once

const size_t AES_BLOCK_SIZE = 16;

class AES {
private:
	unsigned int Nw = 0; // Number of words in a state
	unsigned int Nr = 0; // Number of rounds

	unsigned char* roundKey; // Expanded Key

	void subByte(unsigned char* state);
	void shiftRows(unsigned char* state);
	void mixColumns(unsigned char* state);
	void addRoundKey(unsigned char* state, const unsigned char* roundKey);

	void invSubByte(unsigned char* state);
	void invShiftRows(unsigned char* state);
	void invMixColumns(unsigned char* state);

	void keyExpansion(const std::string& key, unsigned char* roundKey);
	void rotWord(unsigned char temp[4]);
	void subWord(unsigned char temp[4]);
	void rcon(unsigned char temp[4], int round);
	
	friend class AES_Functions;
public:

	explicit AES(const std::string& key);
	~AES();

    AES(AES& other);
    AES& operator=(const AES& other);

	void encryptBlock(unsigned char* state);
	void decryptBlock(unsigned char* state);
};

std::string applyPKCS7Padding(const std::string& data);
std::string removePKCS7Padding(const std::string& data);