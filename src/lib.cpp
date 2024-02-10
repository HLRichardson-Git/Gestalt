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
	size_t numBlocks = (msgLen + 16 - 1) / 16;

	AES aesObject(key);

	// Timing variables
    double totalSubByteTime = 0.0;
    double totalShiftRowsTime = 0.0;
    double totalMixColumnsTime = 0.0;
    double totalAddRoundKeyTime = 0.0;

	for (size_t blockIndex = 0; blockIndex < numBlocks; blockIndex += 16) {
		aesObject.encryptBlock(input + blockIndex);

		// Accumulate timing information
        totalSubByteTime += aesObject.getSubByteTime();
        totalShiftRowsTime += aesObject.getShiftRowsTime();
        totalMixColumnsTime += aesObject.getMixColumnsTime();
        totalAddRoundKeyTime += aesObject.getAddRoundKeyTime();
	}

	// Calculate average times
    double avgSubByteTime = totalSubByteTime / numBlocks;
    double avgShiftRowsTime = totalShiftRowsTime / numBlocks;
    double avgMixColumnsTime = totalMixColumnsTime / numBlocks;
    double avgAddRoundKeyTime = totalAddRoundKeyTime / numBlocks;

	// Display total and average times
    std::cout << "Total SubByte Time: " << totalSubByteTime << " seconds" << std::endl;
    std::cout << "Total ShiftRows Time: " << totalShiftRowsTime << " seconds" << std::endl;
    std::cout << "Total MixColumns Time: " << totalMixColumnsTime << " seconds" << std::endl;
    std::cout << "Total AddRoundKey Time: " << totalAddRoundKeyTime << " seconds" << std::endl;

    std::cout << "Average SubByte Time: " << avgSubByteTime << " seconds per block" << std::endl;
    std::cout << "Average ShiftRows Time: " << avgShiftRowsTime << " seconds per block" << std::endl;
    std::cout << "Average MixColumns Time: " << avgMixColumnsTime << " seconds per block" << std::endl;
    std::cout << "Average AddRoundKey Time: " << avgAddRoundKeyTime << " seconds per block" << std::endl;

	msg.assign(reinterpret_cast<char*>(input), paddedMsgLen);

	//delete[] input;
}

void Message::aes_decrypt_ecb(std::string key)
{
	size_t msgLen = msg.length();
	unsigned char* input = new unsigned char[msgLen];
	std::memcpy(input, msg.c_str(), msgLen);

	AES aesObject(key);
	size_t paddedMsgLen = ((msgLen - 1) / 16 + 1) * 16;
	for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += 16) {
		aesObject.decryptBlock(input + blockIndex);
	}

	size_t origMsgLen = paddedMsgLen - static_cast<size_t>(input[paddedMsgLen - 1]);
	removePCKS7Padding(input, origMsgLen, paddedMsgLen);

	msg.assign(reinterpret_cast<char*>(input), origMsgLen);
}

/*void Message::aes_encrypt_cbc(std::string key)
{
	unsigned char* iv = nonce;

	applyPCKS7Padding(msg);

	AES aesObject(key);
	size_t msgSize = sizeof(msg) / sizeof(msg[0]);
	for (size_t blockIndex = 0; blockIndex < msgSize; blockIndex += 16) {
		xorBlock(msg, iv, blockIndex);
		aesObject.encryptBlock(msg + blockIndex);
		memcpy(iv, msg + blockIndex, 16);
	}
}

void Message::aes_decrypt_cbc(std::string key)
{
	unsigned char* iv = nonce;
	unsigned char* temp[16];

	AES aesObject(key);
	size_t msgSize = sizeof(msg) / sizeof(msg[0]);
	for (size_t blockIndex = 0; blockIndex < msgSize; blockIndex += 16) {
		memcpy(temp, msg + blockIndex, 16);
		aesObject.decryptBlock(msg + blockIndex);
		xorBlock(msg, iv, blockIndex);
		memcpy(iv, temp, 16);
	}

	removePCKS7Padding(msg);
}*/