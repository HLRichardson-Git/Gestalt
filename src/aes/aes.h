/*
 * aes.h
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
 *
 * Author: Hunter L, Richardson
 * Date: 2024-02-11
 */

#pragma once

#include <iostream>
#include <string>
class AES {
private:
	static const unsigned int Nb = 16; // Block size
	unsigned int Nw = 0; // Number of words in a state
	unsigned int Nr = 0; // Number of rounds

	unsigned char* roundKey; // Expanded Key
	
public:

	AES(std::string key);
	~AES() {delete[] roundKey;}

	void encryptBlock(unsigned char* input);
	void decryptBlock(unsigned char* input);

	void subByte(unsigned char state[Nb]);
	void shiftRows(unsigned char state[Nb]);
	void mixColumns(unsigned char state[Nb]);
	void addRoundKey(unsigned char state[Nb], unsigned char* roundKey);

	void invSubByte(unsigned char state[Nb]);
	void invShiftRows(unsigned char state[Nb]);
	void invMixColumns(unsigned char state[Nb]);

	void keyExpansion(std::string key, unsigned char* roundKey);
	void rotWord(unsigned char temp[4]);
	void subWord(unsigned char temp[4]);
	void rcon(unsigned char temp[4], int round);

	unsigned char* getRoundKey();
};

void applyPCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen);
void removePCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen);