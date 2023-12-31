#include "gtest/gtest.h"

#include "../src/aes/aes.h"
#include "../tools/utils.h"
#include "../src/lib.h"

TEST(TestAesECB, RoundtripWith128BitKey) {
	std::vector<unsigned char> inputData = generateRandomData(1);
	Message message(inputData);

	std::string key = "10a58869d74be5a374cf867cfb473859";

	message.aes_encrypt_ecb(key);
	message.aes_decrypt_ecb(key);

	EXPECT_EQ(message.msg, inputData);
}

TEST(TestAesECB, RoundtripWith192BitKey) {
	std::vector<unsigned char> inputData = generateRandomData(1);
	Message message(inputData);

	std::string key = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

	message.aes_encrypt_ecb(key);
	message.aes_decrypt_ecb(key);

	EXPECT_EQ(message.msg, inputData);
}

TEST(TestAesECB, RoundtripWith256BitKey) {
	std::vector<unsigned char> inputData = generateRandomData(1);
	Message message(inputData);

	std::string key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

	message.aes_encrypt_ecb(key);
	message.aes_decrypt_ecb(key);

	EXPECT_EQ(message.msg, inputData);
}

TEST(TestAesCBC, RoundtripWith128BitKey) {
	std::vector<unsigned char> inputData = generateRandomData(1);
	Message message(inputData, AES_CBC, hexStringToBytesVec("00000000000000000000000000000000"));

	std::string key = "10a58869d74be5a374cf867cfb473850";

	message.aes_encrypt_cbc(key);
	message.aes_decrypt_cbc(key);

	EXPECT_EQ(message.msg, inputData);
}

TEST(TestAesCBC, RoundtripWith192BitKey) {
	std::vector<unsigned char> inputData = generateRandomData(1);
	Message message(inputData, AES_CBC, hexStringToBytesVec("00000000000000000000000000000000"));

	std::string key = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

	message.aes_encrypt_cbc(key);
	message.aes_decrypt_cbc(key);

	EXPECT_EQ(message.msg, inputData);
}

TEST(TestAesCBC, RoundtripWith256BitKey) {
	std::vector<unsigned char> inputData = generateRandomData(1);
	Message message(inputData, AES_CBC, hexStringToBytesVec("00000000000000000000000000000000"));

	std::string key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

	message.aes_encrypt_cbc(key);
	message.aes_decrypt_cbc(key);

	EXPECT_EQ(message.msg, inputData);
}

/*TEST(TestAesKeyExpansion, KeyExpansion) {
	std::vector<unsigned char> key = hexStringToBytesVec("10a58869d74be5a374cf867cfb473859");

	AES Key(key);

	std::vector<unsigned char> roundKey = Key.getRoundKey();

	std::vector<unsigned char> expectedVec = hexStringToBytesVec("10a58869d74be5a374cf867cfb473859b1a2436666e9a6c5122620b9e96118e05c0fa2783ae604bd28c02404c1a13ce46ae4cb005002cfbd78c2ebb9b963d75d99ea8756c9e848ebb12aa3520849740fb278f1667b90b98dcaba1adfc2f36ed09fe78143e47738ce2ecd2211ec3e4cc16dcef98d89b9c143a774e3524b4aaf933bb7253eb20ee47d157a072f5e30a8bc24754066967ba41b8301a334dd310b88d55e84a7432520bcc02483881d158800");

	EXPECT_EQ(roundKey, expectedVec);
}

TEST(TestAesFunctions, SubByte) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));

	std::vector<unsigned char> inputData = generateRandomData(1);
	// Prepare input data
	std::vector<unsigned char> state = inputData;

	// Expected output after SubByte transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("ca06c4f90eb3d90a928a44100fa007cb");

	// Call the SubByte function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.subByte(state, blockIndex);
	}
	//aesObject.subByte(state, 0);

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}

TEST(TestAesFunctions, shiftRows) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));
	// Prepare input data
	std::vector<unsigned char> inputData = generateRandomData(1);
	std::vector<unsigned char> state = inputData;

	// Expected output after shiftRows transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("cab344cb0e8a07f992a0c40a0f06d910");

	// Call the shiftRows function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.shiftRows(state, blockIndex);
	}

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}

TEST(TestAesFunctions, mixColumns) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));
	// Prepare input data
	std::vector<unsigned char> inputData = generateRandomData(1);
	std::vector<unsigned char> state = inputData;

	// Expected output after mixColumns transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("ceb0b73f67f19a760a94bfdddd6390ee");

	// Call the mixColumns function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.mixColumns(state, blockIndex);
	}

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}

TEST(TestAesFunctions, addRoundKey) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));
	// Prepare input data
	std::vector<unsigned char> inputData = generateRandomData(1);
	std::vector<unsigned char> state = inputData;
	std::vector<unsigned char> keyStr = hexStringToBytesVec("10a58869d74be5a374cf867cfb473859");

	// Expected output after addRoundKey transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("10a58869d74be5a374cf867cfb473859");

	// Call the addRoundKey function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.addRoundKey(state, keyStr, blockIndex, 0);
	}

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}

TEST(TestAesFunctions, invSubByte) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));
	// Prepare input data
	std::vector<unsigned char> inputData = generateRandomData(1);
	std::vector<unsigned char> state = inputData;

	// Expected output after invSubByte transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("9a3b83a73803816de6ad37bcc7e62cec");

	// Call the invSubByte function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.invSubByte(state, blockIndex);
	}

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}

TEST(TestAesFunctions, invShiftRows) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));
	// Prepare input data
	std::vector<unsigned char> inputData = generateRandomData(1);
	std::vector<unsigned char> state = inputData;

	// Expected output after invShiftRows transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("89446224c266c7fe223b0bf0fd6b5816");

	// Call the invShiftRows function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.invShiftRows(state, blockIndex);
	}

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}

TEST(TestAesFunctions, invMixColumns) {
	AES aesObject(hexStringToBytesVec("10a58869d74be5a374cf867cfb473859"));
	// Prepare input data
	std::vector<unsigned char> inputData = generateRandomData(1);
	std::vector<unsigned char> state = inputData;

	// Expected output after invMixColumns transformation
	std::vector<unsigned char> expectedOutput = hexStringToBytesVec("89660b16c23b5824226b62fefd44c7f0");

	// Call the invMixColumns function and test
	for (size_t blockIndex = 0; blockIndex < state.size(); blockIndex += 16) {
		aesObject.invMixColumns(state, blockIndex);
	}

	// Check if the output matches the expected output
	EXPECT_EQ(true, true);
}*/