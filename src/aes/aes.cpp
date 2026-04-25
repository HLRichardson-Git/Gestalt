/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aes.cpp
 *
 * This file contains the implementation of Gestalts AES security functions.
 */

#include <cstring>

#include <gestalt/aes.h>
#include "aesCore.h"

/*
 * Encrypts an arbitrarily sized input with AES_ECB.
 *
 * @param msg  The plaintext as raw bytes.
 * @param key  The 128, 192, or 256 bit key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes encryptAESECB(const SecureBytes& msg, const SecureBytes& key) {
    AES cipher(key);

    SecureBytes paddedMsg = applyPKCS7Padding(msg);
    size_t paddedMsgLen = paddedMsg.size();

    unsigned char* input = new unsigned char[paddedMsgLen];
    std::memcpy(input, paddedMsg.data(), paddedMsgLen);

    for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += AES_BLOCK_SIZE) {
        cipher.encryptBlock(input + blockIndex);
    }

    SecureBytes result(paddedMsgLen);
    std::memcpy(result.data(), input, paddedMsgLen);

    delete[] input;
    return result;
}

/*
 * Decrypts an arbitrarily sized input with AES_ECB.
 *
 * @param ciphertext  The encrypted bytes.
 * @param key         The 128, 192, or 256 bit key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes decryptAESECB(const SecureBytes& ciphertext, const SecureBytes& key) {
    AES cipher(key);

    size_t msgLen = ciphertext.size();

    unsigned char* input = new unsigned char[msgLen];
    std::memcpy(input, ciphertext.data(), msgLen);

    for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += AES_BLOCK_SIZE) {
        cipher.decryptBlock(input + blockIndex);
    }

    SecureBytes result(msgLen);
    std::memcpy(result.data(), input, msgLen);

    delete[] input;
    return removePKCS7Padding(result);
}

/*
 * Encrypts an arbitrarily sized input with AES_CBC.
 *
 * @param msg  The plaintext as raw bytes.
 * @param iv   The initialization vector as raw bytes.
 * @param key  The 128, 192, or 256 bit key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes encryptAESCBC(const SecureBytes& msg, const SecureBytes& iv, const SecureBytes& key) {
    AES cipher(key);

    SecureBytes paddedMsg = applyPKCS7Padding(msg);
    size_t paddedMsgLen = paddedMsg.size();

    unsigned char* input = new unsigned char[paddedMsgLen];
    std::memcpy(input, paddedMsg.data(), paddedMsgLen);

    SecureBytes currentIV = iv;
    for (size_t blockIndex = 0; blockIndex < paddedMsgLen; blockIndex += AES_BLOCK_SIZE) {
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
            input[blockIndex + i] ^= currentIV[i];
        }
        cipher.encryptBlock(input + blockIndex);
        std::memcpy(currentIV.data(), input + blockIndex, AES_BLOCK_SIZE);
    }

    SecureBytes result(paddedMsgLen);
    std::memcpy(result.data(), input, paddedMsgLen);

    delete[] input;
    return result;
}

/*
 * Decrypts an arbitrarily sized input with AES_CBC.
 *
 * @param ciphertext  The encrypted bytes.
 * @param iv          The initialization vector as raw bytes.
 * @param key         The 128, 192, or 256 bit key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes decryptAESCBC(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key) {
    AES cipher(key);

    size_t msgLen = ciphertext.size();

    unsigned char* input = new unsigned char[msgLen];
    std::memcpy(input, ciphertext.data(), msgLen);

    SecureBytes currentIV = iv;
    SecureBytes nextIV(AES_BLOCK_SIZE);
    for (size_t blockIndex = 0; blockIndex < msgLen; blockIndex += AES_BLOCK_SIZE) {
        std::memcpy(nextIV.data(), input + blockIndex, AES_BLOCK_SIZE);
        cipher.decryptBlock(input + blockIndex);
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
            input[blockIndex + i] ^= currentIV[i];
        }
        currentIV = nextIV;
    }

    SecureBytes result(msgLen);
    std::memcpy(result.data(), input, msgLen);

    delete[] input;
    return removePKCS7Padding(result);
}