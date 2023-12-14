#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>

class AES {
private:
	static const unsigned int Nb = 16; // Block size
	unsigned int Nw = 0; // Number of words in a state
	unsigned int Nr = 0; // Number of rounds

	std::array<unsigned char, Nb> state;
	unsigned char* roundKey; // Expanded Key

public:

	AES(std::string key);

	void encryptBlock(std::vector<unsigned char>& input, size_t blockIndex);
	void decryptBlock(std::vector<unsigned char>& input, size_t blockIndex);

	void subByte();
	void shiftRows();
	void mixColumns();
	void addRoundKey(unsigned char* roundKey);

	void invSubByte();
	void invShiftRows();
	void invMixColumns();

	void keyExpansion(std::string key, unsigned char* roundKey);
	void rotWord(unsigned char temp[4]);
	void subWord(unsigned char temp[4]);
	void rcon(unsigned char temp[4], int round);

	unsigned char* getRoundKey();
};

void applyPCKS7Padding(std::vector<unsigned char>& input);
void removePCKS7Padding(std::vector<unsigned char>& input);