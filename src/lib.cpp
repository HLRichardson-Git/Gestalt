// Internal Dependencies
#include "lib.h"
#include "../tools/utils.h"

void Message::aes_encrypt_ecb(std::string key)
{	
	size_t msgLen = msg.length();
	size_t paddedMsgLen = msgLen + 16 - (msgLen % 16);
	unsigned char* input = new unsigned char[paddedMsgLen];
	std::memcpy(input, msg.c_str(), msgLen);

	applyPCKS7Padding(input, msgLen, paddedMsgLen);
	AES aesObject(key);

	for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += 16) {
		aesObject.encryptBlock(input + blockIndex);
	}

	msg.assign(reinterpret_cast<char*>(input), paddedMsgLen);

	delete[] input;
}

void Message::aes_decrypt_ecb(std::string key)
{
	size_t msgLen = msg.length();
	//size_t paddedMsgLen = ((msgLen - 1) / 16 + 1) * 16;
	unsigned char* input = new unsigned char[msgLen];
	std::memcpy(input, msg.c_str(), msgLen);

	AES aesObject(key);

	for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += 16) {
		aesObject.decryptBlock(input + blockIndex);
	}

	size_t origMsgLen = msgLen - static_cast<size_t>(input[msgLen - 1]);
	removePCKS7Padding(input, origMsgLen, msgLen);

	msg.assign(reinterpret_cast<char*>(input), origMsgLen);

	delete[] input;
}

void Message::aes_encrypt_cbc(std::string key)
{
	size_t msgLen = msg.length();
	size_t paddedMsgLen = msgLen + 16 - (msgLen % 16);
	unsigned char* input = new unsigned char[paddedMsgLen];
	std::memcpy(input, msg.c_str(), msgLen);
	
	std::string iv = nonce;

	applyPCKS7Padding(input, msgLen, paddedMsgLen);

	AES aesObject(key);

	for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += 16) {
		xorBlock(input, iv, blockIndex);
		aesObject.encryptBlock(input + blockIndex);
		iv.assign(reinterpret_cast<char*>(input + blockIndex), 16);
	}

	msg.assign(reinterpret_cast<char*>(input), paddedMsgLen);

	delete[] input;
}

void Message::aes_decrypt_cbc(std::string key)
{
	size_t msgLen = msg.length();
	unsigned char* input = new unsigned char[msgLen];
	std::memcpy(input, msg.c_str(), msgLen);

	std::string iv = nonce;
	std::string tmp = "";

	AES aesObject(key);

	for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += 16) {
		//memcpy(temp, input + blockIndex, 16);
		tmp.assign(reinterpret_cast<char*>(input + blockIndex), 16);
		aesObject.decryptBlock(input + blockIndex);
		xorBlock(input, iv, blockIndex);
		//memcpy(iv, temp, 16);
		iv = tmp;
		//iv.assign(reinterpret_cast<char*>(tmp), 16);
	}

	size_t origMsgLen = msgLen - static_cast<size_t>(input[msgLen - 1]);
	removePCKS7Padding(input, origMsgLen, msgLen);

	msg.assign(reinterpret_cast<char*>(input), origMsgLen);

	delete[] input;
}