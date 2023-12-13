#pragma once

#include <iomanip>
#include <string>
#include <vector>

class AES {
private:
	const unsigned int Nb = 4; // Block size
	unsigned int Nw = 0; // Number of words in a state
	unsigned int Nr = 0; // Number of rounds

	unsigned char* roundKey; // Expanded Key

public:

	AES(std::string key);

	void encryptBlock(std::vector<unsigned char>& input, size_t blockIndex);
	void decryptBlock(std::vector<unsigned char>& input, size_t blockIndex);

	void subByte(unsigned char state[4][4]);
	void shiftRows(unsigned char state[4][4]);
	void mixColumns(unsigned char state[4][4]);
	void addRoundKey(unsigned char state[4][4], unsigned char* roundKey);

	void invSubByte(unsigned char state[4][4]);
	void invShiftRows(unsigned char state[4][4]);
	void invMixColumns(unsigned char state[4][4]);

	void keyExpansion(std::string key, unsigned char* roundKey);
	void rotWord(unsigned char temp[4]);
	void subWord(unsigned char temp[4]);
	void rcon(unsigned char temp[4], int round);
};

void applyPCKS7Padding(std::vector<unsigned char>& input);
void removePCKS7Padding(std::vector<unsigned char>& input);