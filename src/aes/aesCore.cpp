/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aesCore.cpp
 *
 * This file contains the implementation of the AES (Advanced Encryption Standard) algorithm.
 * AES is a symmetric encryption algorithm used for secure data transmission and storage.
 * This implementation supports AES with key sizes of 128, 192, and 256 bits.
 *
 * References:
 * - The Design of Rijndael: AES - The Advanced Encryption Standard (https://csrc.nist.gov/publications/detail/fips/197/final)
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 * 
 * This implementation follows the specifications outlined in the FIPS 197 standard,
 * which defines the AES algorithm. AES operates on blocks of data, each consisting
 * of a 4x4 matrix of bytes, known as the "state" in AES terminology. In this implementation,
 * the state is represented by the `unsigned char state[Nb]` array, where `Nb` is the block size
 * for AES, which is 16.
 * 
 * The state matrix is structured as follows:
 * 
 *    [S0,0  S0,1  S0,2  S0,3]
 *    [S1,0  S1,1  S1,2  S1,3]
 *    [S2,0  S2,1  S2,2  S2,3]
 *    [S3,0  S3,1  S3,2  S3,3]
 * 
 * Each element of the matrix represents a single byte of data. However, in this
 * implementation, the state matrix is linearized into a one-dimensional array
 * (`state`) for ease of manipulation and storage. The mapping from the 2-dimensional
 * matrix to the 1-dimensional array is as follows:
 * 
 *    state[0]   state[4]   state[8]   state[12]
 *    state[1]   state[5]   state[9]   state[13]
 *    state[2]   state[6]   state[10]  state[14]
 *    state[3]   state[7]   state[11]  state[15]
 * 
 * This linear representation simplifies the implementation of AES operations, 
 * making it more efficient and easier to work with while preserving the structure
 * defined in the AES standard.
 */

#include <iostream>
#include <string>
#include <cstring>

#include "aesCore.h"
#include "aesConstants.h"

enum class AESKeySize : int {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
};

/*
 * AES Constructor
 *
 * Initializes the AES instance with the given key.
 * Sets the number of words in the key schedule (Nw) and the number of rounds (Nr) based on the key size.
 * Performs key expansion to generate the round keys.
 *
 * @param key A string representing the encryption key in hexadecimal format.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
AES::AES(const std::string& key) {
    // // Determine key size and set Nw (number of words in key) and Nr (number of rounds)
    switch (key.size() * 4) {
    case static_cast<int>(AESKeySize::AES_128):
        Nw = 4;
        Nr = 10;
        break;
    case static_cast<int>(AESKeySize::AES_192):
        Nw = 6;
        Nr = 12;
        break;
    case static_cast<int>(AESKeySize::AES_256):
        Nw = 8;
        Nr = 14;
        break;
    default:
        throw std::invalid_argument("Invalid key size. Expected 128, 192, or 256 bits.");
    }

    // Allocate memory for round keys and perform key expansion
    roundKey = new unsigned char[Nb * (Nr + 1)];
    keyExpansion(key, roundKey);
}

// Deconstructor 
AES::~AES() {
    delete[] roundKey;
}

// Copy constructor
AES::AES(AES& other) {
    Nw = other.Nw;
    Nr = other.Nr;
    roundKey = new unsigned char[Nb * (Nr + 1)];
    std::copy(other.roundKey, other.roundKey + Nb * (Nr + 1), roundKey);
}

// Assignment operator
AES& AES::operator=(const AES& other) {
    if (this != &other) {
        delete[] roundKey;
        Nw = other.Nw;
        Nr = other.Nr;
        roundKey = new unsigned char[Nb * (Nr + 1)];
        std::copy(other.roundKey, other.roundKey + Nb * (Nr + 1), roundKey);
    }
    return *this;
}

/*
 * Encrypts a single AES block (16 bytes) in place.
 *
 * @param input A pointer to the input block to be encrypted.
 */
void AES::encryptBlock(unsigned char* input) {
    // Initialize state with the input block
    unsigned char state[Nb];
    memcpy(state, input, Nb);

    // Perform AES encryption rounds
    addRoundKey(state, roundKey);
    size_t round = 1;
    while (round < Nr) {
        subByte(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKey + (Nb * round));
        round++;
    }
    subByte(state);
    shiftRows(state);
    addRoundKey(state, roundKey + Nr * Nb);

    // Copy the encrypted state back to the input block
    memcpy(input, state, Nb);
}

/*
 * Decrypts a single AES block (16 bytes) in place.
 *
 * @param input A pointer to the input block to be decrypted.
 */
void AES::decryptBlock(unsigned char* input) {
    // Initialize state with the input block
    unsigned char state[Nb];
    memcpy(state, input, Nb);

    // Perform AES decryption rounds
    addRoundKey(state, roundKey + Nr * Nb);
    size_t round = Nr - 1;
    while (round > 0) {
        invShiftRows(state);
        invSubByte(state);
        addRoundKey(state, roundKey + (Nb * round));
        invMixColumns(state);
        round--;
    }
    invShiftRows(state);
    invSubByte(state);
    addRoundKey(state, roundKey);

    // Copy the decrypted state back to the input block
    memcpy(input, state, Nb);
}

/*
 * Performs SubBytes operation on each byte of the state using the S-box lookup table.
 *
 * @param state The state array to be transformed.
 */
void AES::subByte(unsigned char state[Nb]) {
    for (size_t i = 0; i < Nb; i++) {
        state[i] = SBOX[state[i]];
    }
}

/*
 * Performs ShiftRows operation on the state.
 *
 * @param state The state array to be transformed.
 */
void AES::shiftRows(unsigned char state[Nb]) {
    unsigned char tmp[Nb];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];
	
	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];
	
	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

    memcpy(state, tmp, Nb);
}

/*
 * Performs MixColumns operation on the state.
 *
 * @param state The state array to be transformed.
 */
void AES::mixColumns(unsigned char state[Nb]) {
    unsigned char tmp[Nb];

    tmp[0] = GF_MUL_TABLE[2][state[0]] ^ GF_MUL_TABLE[3][state[1]] ^ state[2] ^ state[3];
    tmp[1] = state[0] ^ GF_MUL_TABLE[2][state[1]] ^ GF_MUL_TABLE[3][state[2]] ^ state[3];
    tmp[2] = state[0] ^ state[1] ^ GF_MUL_TABLE[2][state[2]] ^ GF_MUL_TABLE[3][state[3]];
    tmp[3] = GF_MUL_TABLE[3][state[0]] ^ state[1] ^ state[2] ^ GF_MUL_TABLE[2][state[3]];

    tmp[4] = GF_MUL_TABLE[2][state[4]] ^ GF_MUL_TABLE[3][state[5]] ^ state[6] ^ state[7];
    tmp[5] = state[4] ^ GF_MUL_TABLE[2][state[5]] ^ GF_MUL_TABLE[3][state[6]] ^ state[7];
    tmp[6] = state[4] ^ state[5] ^ GF_MUL_TABLE[2][state[6]] ^ GF_MUL_TABLE[3][state[7]];
    tmp[7] = GF_MUL_TABLE[3][state[4]] ^ state[5] ^ state[6] ^ GF_MUL_TABLE[2][state[7]];

    tmp[8] = GF_MUL_TABLE[2][state[8]] ^ GF_MUL_TABLE[3][state[9]] ^ state[10] ^ state[11];
    tmp[9] = state[8] ^ GF_MUL_TABLE[2][state[9]] ^ GF_MUL_TABLE[3][state[10]] ^ state[11];
    tmp[10] = state[8] ^ state[9] ^ GF_MUL_TABLE[2][state[10]] ^ GF_MUL_TABLE[3][state[11]];
    tmp[11] = GF_MUL_TABLE[3][state[8]] ^ state[9] ^ state[10] ^ GF_MUL_TABLE[2][state[11]];

    tmp[12] = GF_MUL_TABLE[2][state[12]] ^ GF_MUL_TABLE[3][state[13]] ^ state[14] ^ state[15];
    tmp[13] = state[12] ^ GF_MUL_TABLE[2][state[13]] ^ GF_MUL_TABLE[3][state[14]] ^ state[15];
    tmp[14] = state[12] ^ state[13] ^ GF_MUL_TABLE[2][state[14]] ^ GF_MUL_TABLE[3][state[15]];
    tmp[15] = GF_MUL_TABLE[3][state[12]] ^ state[13] ^ state[14] ^ GF_MUL_TABLE[2][state[15]];

    memcpy(state, tmp, Nb);
}

/*
 * Adds the round key to the state using bitwise XOR operation.
 *
 * @param state The state array to which the round key is added.
 * @param roundKey Pointer to the round key array.
 */
void AES::addRoundKey(unsigned char state[Nb], const unsigned char* roundKey) {
    for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/*
 * Performs invSubBytes operation on each byte of the state using the inverse S-box lookup table.
 *
 * @param state The state array to be transformed.
 */
void AES::invSubByte(unsigned char state[Nb]) {
    for (size_t i = 0; i < Nb; i++) {
        state[i] = INVSBOX[state[i]];
    }
}

/*
 * Performs invShiftRows operation on the state.
 *
 * @param state The state array to be transformed.
 */
void AES::invShiftRows(unsigned char state[Nb]) {
    unsigned char tmp[Nb];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

    memcpy(state, tmp, Nb);
}

/*
 * Performs invMixColumns operation on the state.
 *
 * @param state The state array to be transformed.
 */
void AES::invMixColumns(unsigned char state[Nb]) {
    unsigned char tmp[Nb];

    tmp[0]  = GF_MUL_TABLE[14][state[0]] ^ GF_MUL_TABLE[11][state[1]] ^ GF_MUL_TABLE[13][state[2]] ^ GF_MUL_TABLE[9][state[3]];
    tmp[1]  = GF_MUL_TABLE[9][state[0]] ^ GF_MUL_TABLE[14][state[1]] ^ GF_MUL_TABLE[11][state[2]] ^ GF_MUL_TABLE[13][state[3]];
    tmp[2]  = GF_MUL_TABLE[13][state[0]] ^ GF_MUL_TABLE[9][state[1]] ^ GF_MUL_TABLE[14][state[2]] ^ GF_MUL_TABLE[11][state[3]];
    tmp[3]  = GF_MUL_TABLE[11][state[0]] ^ GF_MUL_TABLE[13][state[1]] ^ GF_MUL_TABLE[9][state[2]] ^ GF_MUL_TABLE[14][state[3]];

    tmp[4]  = GF_MUL_TABLE[14][state[4]] ^ GF_MUL_TABLE[11][state[5]] ^ GF_MUL_TABLE[13][state[6]] ^ GF_MUL_TABLE[9][state[7]];
    tmp[5]  = GF_MUL_TABLE[9][state[4]] ^ GF_MUL_TABLE[14][state[5]] ^ GF_MUL_TABLE[11][state[6]] ^ GF_MUL_TABLE[13][state[7]];
    tmp[6]  = GF_MUL_TABLE[13][state[4]] ^ GF_MUL_TABLE[9][state[5]] ^ GF_MUL_TABLE[14][state[6]] ^ GF_MUL_TABLE[11][state[7]];
    tmp[7]  = GF_MUL_TABLE[11][state[4]] ^ GF_MUL_TABLE[13][state[5]] ^ GF_MUL_TABLE[9][state[6]] ^ GF_MUL_TABLE[14][state[7]];

    tmp[8]  = GF_MUL_TABLE[14][state[8]] ^ GF_MUL_TABLE[11][state[9]] ^ GF_MUL_TABLE[13][state[10]] ^ GF_MUL_TABLE[9][state[11]];
    tmp[9]  = GF_MUL_TABLE[9][state[8]] ^ GF_MUL_TABLE[14][state[9]] ^ GF_MUL_TABLE[11][state[10]] ^ GF_MUL_TABLE[13][state[11]];
    tmp[10] = GF_MUL_TABLE[13][state[8]] ^ GF_MUL_TABLE[9][state[9]] ^ GF_MUL_TABLE[14][state[10]] ^ GF_MUL_TABLE[11][state[11]];
    tmp[11] = GF_MUL_TABLE[11][state[8]] ^ GF_MUL_TABLE[13][state[9]] ^ GF_MUL_TABLE[9][state[10]] ^ GF_MUL_TABLE[14][state[11]];

    tmp[12] = GF_MUL_TABLE[14][state[12]] ^ GF_MUL_TABLE[11][state[13]] ^ GF_MUL_TABLE[13][state[14]] ^ GF_MUL_TABLE[9][state[15]];
    tmp[13] = GF_MUL_TABLE[9][state[12]] ^ GF_MUL_TABLE[14][state[13]] ^ GF_MUL_TABLE[11][state[14]] ^ GF_MUL_TABLE[13][state[15]];
    tmp[14] = GF_MUL_TABLE[13][state[12]] ^ GF_MUL_TABLE[9][state[13]] ^ GF_MUL_TABLE[14][state[14]] ^ GF_MUL_TABLE[11][state[15]];
    tmp[15] = GF_MUL_TABLE[11][state[12]] ^ GF_MUL_TABLE[13][state[13]] ^ GF_MUL_TABLE[9][state[14]] ^ GF_MUL_TABLE[14][state[15]];

    memcpy(state, tmp, Nb);
}

/*
 * Key Expansion
 *
 * Expands the original key into a key schedule for encryption and decryption.
 * The key schedule is stored in the roundKey array.
 *
 * @param key The original encryption key.
 * @param roundKey Pointer to the array where the round keys will be stored.
 */
void AES::keyExpansion(const std::string& key, unsigned char* roundKey) {
    unsigned char temp[4] = { 0x00, 0x00, 0x00, 0x00 };

    unsigned int i = 0;
    for (i = 0; i < 4 * Nw; i++) {
        int index = i * 2;
        // Extract two hexadecimal characters
        std::string hexByte = key.substr(index, 2);

        // Convert the hexadecimal string to an unsigned char
        roundKey[i] = static_cast<unsigned char>(std::stoi(hexByte, nullptr, 16));
    }

    i = 4 * Nw;
    while (i < Nb * (Nr + 1)) {
        temp[0] = roundKey[i - 4 + 0];
        temp[1] = roundKey[i - 4 + 1];
        temp[2] = roundKey[i - 4 + 2];
        temp[3] = roundKey[i - 4 + 3];

        if (i / 4 % Nw == 0) {
            rotWord(temp);
            subWord(temp);
            rcon(temp, (i / (Nw * 4)) - 1);
        }
        else if (Nw > 6 && i / 4 % Nw == 4) {
            subWord(temp);
        }

        roundKey[i + 0] = roundKey[i + 0 - 4 * Nw] ^ temp[0];
        roundKey[i + 1] = roundKey[i + 1 - 4 * Nw] ^ temp[1];
        roundKey[i + 2] = roundKey[i + 2 - 4 * Nw] ^ temp[2];
        roundKey[i + 3] = roundKey[i + 3 - 4 * Nw] ^ temp[3];

        i += 4;
    }
}

/*
 * Performs rotWord operation on the temp array.
 *
 * @param temp The state array to be transformed.
 */
void AES::rotWord(unsigned char temp[4]) {
    unsigned char temp2 = temp[0];
    for (int x = 0; x < 3; x++) {
        temp[x] = temp[x + 1];
    }
    temp[3] = temp2;
}

/*
 * Performs subWord operation on the temp array.
 *
 * @param temp The state array to be transformed.
 */
void AES::subWord(unsigned char temp[4]) {
    for (int x = 0; x < 4; x++) {
        temp[x] = SBOX[temp[x]];
    }
}

/*
 * Performs rCon operation on the temp array.
 *
 * @param temp The state array to be transformed.
 */
void AES::rcon(unsigned char temp[4], int round) {
    temp[0] ^= RCON[round];
}

// Gets roundKey from testAesFunctions class
const unsigned char* TestAesFunctions::testKeyExpansion() {
    return this->roundKey;
}

// Uses subByte function from AES for testing
void TestAesFunctions::testSubByte(unsigned char state[Nb]) {
    this->aesObject.subByte(state);
}

// Uses shiftRows function from AES for testing
void TestAesFunctions::testShiftRows(unsigned char state[Nb]) {
    this->aesObject.shiftRows(state);
}

// Uses mixColumns function from AES for testing
void TestAesFunctions::testMixColumns(unsigned char state[Nb]) {
    this->aesObject.mixColumns(state);
}

// Uses addRoundKey function from AES for testing
void TestAesFunctions::testAddRoundKey(unsigned char state[Nb], const unsigned char* roundKey) {
    this->aesObject.addRoundKey(state, roundKey);
}

// Uses invSubByte function from AES for testing
void TestAesFunctions::testInvSubByte(unsigned char state[Nb]) {
    this->aesObject.invSubByte(state);
}

// Uses invShiftRows function from AES for testing
void TestAesFunctions::testInvShiftRows(unsigned char state[Nb]) {
    this->aesObject.invShiftRows(state);
}

// Uses invMixColumns function from AES for testing
void TestAesFunctions::testInvMixColumns(unsigned char state[Nb]) {
    this->aesObject.invMixColumns(state);
}

/*
 * Applies PKCS7 padding to the input message.
 * PKCS7 padding is a method used to pad messages to a multiple of the block size.
 * The padding value is the number of bytes added, each byte being equal to the number of bytes added.
 *
 * @param input Pointer to the input message buffer.
 * @param origMsgLen The original length of the message in bytes.
 * @param paddedMsgLen The length of the padded message buffer.
 */
void applyPCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen) {
    // Calculate the number of elements in the last block
    int elementsInLastBlock = 16 - (origMsgLen % 16);
    unsigned char paddingValue = static_cast<unsigned char>(elementsInLastBlock);
    // Pad the message with the padding value
    for (size_t i = origMsgLen; i < paddedMsgLen; i++) {
        input[i] = paddingValue;
    }
}

/*
 * Removes PKCS7 padding from the input message.
 * PKCS7 padding is removed by examining the last byte of the padded message,
 * which indicates the number of bytes added as padding. This value is used
 * to determine how many bytes to remove from the end of the message.
 *
 * @param input Pointer to the padded message buffer.
 * @param origMsgLen The original length of the message in bytes.
 * @param paddedMsgLen The length of the padded message buffer.
 */
void removePCKS7Padding(unsigned char* input, size_t origMsgLen, size_t paddedMsgLen) {
    unsigned int padding_value = static_cast<unsigned int>(input[paddedMsgLen - 1]);
    size_t amount_to_remove = paddedMsgLen - padding_value;
    if (amount_to_remove > origMsgLen) {
        // Invalid padding, do nothing
        return;
    }
    // Adjust input size to the actual decrypted message length
    input[amount_to_remove] = '\0'; // Null-terminate the string at the end of the decrypted message
}

