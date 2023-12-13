// Internal Dependencies
#include "lib.h"
#include "../tools/utils.h"

void Message::aes_encrypt_ecb(std::string key)
{
	//std::vector<unsigned char> keyVec = hexStringToBytesVec(key);

	applyPCKS7Padding(msg);

	AES aesObject(key);
	//std::vector<unsigned char> roundKey = aesObject.getRoundKey();
	//unsigned char roundKey = aesObject.getRoundKey;
	for (size_t blockIndex = 0; blockIndex < msg.size(); blockIndex += 16) {
		aesObject.encryptBlock(msg, blockIndex);
	}
}

void Message::aes_decrypt_ecb(std::string key)
{
	//std::vector<unsigned char> keyVec = hexStringToBytesVec(key);

	AES aesObject(key);
	for (size_t blockIndex = 0; blockIndex < msg.size(); blockIndex += 16) {
		aesObject.decryptBlock(msg, blockIndex);
	}

	removePCKS7Padding(msg);
}

void Message::aes_encrypt_cbc(std::string key)
{
	//std::vector<unsigned char> keyVec = hexStringToBytesVec(key);
	std::vector<unsigned char> iv = nonce;

	applyPCKS7Padding(msg);

	AES aesObject(key);
	for (size_t blockIndex = 0; blockIndex < msg.size(); blockIndex += 16) {
		xorBlock(msg, iv, blockIndex);
		aesObject.encryptBlock(msg, blockIndex);
		std::copy(msg.begin() + blockIndex, msg.begin() + blockIndex + 16, iv.begin());
	}
}

void Message::aes_decrypt_cbc(std::string key)
{
	//std::vector<unsigned char> keyVec = hexStringToBytesVec(key);
	std::vector<unsigned char> iv = nonce;
	std::vector<unsigned char> temp;

	AES aesObject(key);
	for (size_t blockIndex = 0; blockIndex < msg.size(); blockIndex += 16) {
		std::vector<unsigned char> temp(msg.begin() + blockIndex, msg.begin() + blockIndex + 16);
		aesObject.decryptBlock(msg, blockIndex);
		xorBlock(msg, iv, blockIndex);
		iv = temp;
	}

	removePCKS7Padding(msg);
}