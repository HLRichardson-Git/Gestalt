#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>

class AES {
private:
	static const unsigned int Nb = 4; // Block size
	unsigned int Nw = 0; // Number of words in a state
	unsigned int Nr = 0; // Number of rounds

	unsigned char* roundKey; // Expanded Key

public:

	AES(std::string key);
	~AES() {delete[] roundKey;}

	void encryptBlock(std::vector<unsigned char>& input, size_t blockIndex);
	void decryptBlock(std::vector<unsigned char>& input, size_t blockIndex);

	void subByte(unsigned char state[Nb][Nb]);
	void shiftRows(unsigned char state[Nb][Nb]);
	void mixColumns(unsigned char state[Nb][Nb]);
	void addRoundKey(unsigned char state[Nb][Nb], unsigned char* roundKey);

	void invSubByte(unsigned char state[Nb][Nb]);
	void invShiftRows(unsigned char state[Nb][Nb]);
	void invMixColumns(unsigned char state[Nb][Nb]);

	void keyExpansion(std::string key, unsigned char* roundKey);
	void rotWord(unsigned char temp[4]);
	void subWord(unsigned char temp[4]);
	void rcon(unsigned char temp[4], int round);

	unsigned char* getRoundKey();
};

void applyPCKS7Padding(std::vector<unsigned char>& input);
void removePCKS7Padding(std::vector<unsigned char>& input);