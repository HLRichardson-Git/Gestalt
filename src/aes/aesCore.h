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

#include <vector>
#include <array>

const size_t AES_BLOCK_SIZE = 16;
//typedef unsigned char aesBlock[AES_BLOCK_SIZE];
//using aesBlock = unsigned char[AES_BLOCK_SIZE];
using aesBlock = std::array<unsigned char, AES_BLOCK_SIZE>;

class AES {
private:
	static const unsigned int Nb = 16; // Block size
	unsigned int Nw = 0; // Number of words in a state
	unsigned int Nr = 0; // Number of rounds

	unsigned char* roundKey; // Expanded Key

	void subByte(aesBlock& state);
	void shiftRows(aesBlock& state);
	void mixColumns(aesBlock& state);
	void addRoundKey(aesBlock& state, const unsigned char* roundKey);
	//void addRoundKey(unsigned char state[Nb], const unsigned char* roundKey);

	void invSubByte(aesBlock& state);
	void invShiftRows(aesBlock& state);
	void invMixColumns(aesBlock& state);

	void keyExpansion(const std::string& key, unsigned char* roundKey);
	void rotWord(unsigned char temp[4]);
	void subWord(unsigned char temp[4]);
	void rcon(unsigned char temp[4], int round);
	
	friend class AES_Functions;
public:

	explicit AES(const std::string& key);
	~AES();

	// Copy constructor
    AES(AES& other);

	// Assignment operator
    AES& operator=(const AES& other);

	void encryptBlock(aesBlock& state);
	void decryptBlock(aesBlock& state);
};

// Friend class to test components of AES class
class AES_Functions {
private:
	static const unsigned int Nb = 16; // Block size
	AES aesObject;
	unsigned char roundKey[Nb * 15]; // Array to hold round key
public:

	AES_Functions() : aesObject("10a58869d74be5a374cf867cfb473859") {
        aesObject.keyExpansion("10a58869d74be5a374cf867cfb473859", roundKey);
    }

	const unsigned char* testKeyExpansion();

    void testSubByte(aesBlock& state);
	void testShiftRows(aesBlock& state);
	void testMixColumns(aesBlock& state);
	void testAddRoundKey(aesBlock& state, const unsigned char* roundKey);
	//void testAddRoundKey(unsigned char state[Nb], const unsigned char* roundKey);

	void testInvSubByte(aesBlock& state);
	void testInvShiftRows(aesBlock& state);
	void testInvMixColumns(aesBlock& state);
};

std::string applyPKCS7Padding(const std::string& data);
std::vector<aesBlock> convertToAESBlocks(const std::string& str);
std::string aesBlocksToHexString(const std::vector<aesBlock>& blocks);

//void removePCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen);
std::string removePKCS7Padding(const std::string& data);
std::string aesBlocksToBytesString(const std::vector<aesBlock>& blocks);