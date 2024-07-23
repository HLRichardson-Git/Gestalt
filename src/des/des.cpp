/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.cpp
 *
 * This file contains the implementation of Gestalts DES & 3DES security functions.
 */

#include <string>

#include <gestalt/des.h>
#include "des/desCore.h"

std::string desEncryptECB(const std::string& plaintext, const std::string& key) {
    validateKey(key);
    DES des(key);

    std::string paddedPlaintext = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = stringToBlocks(paddedPlaintext);

    std::vector<uint64_t> encryptedBlocks;
    for (uint64_t block : blocks) {
        encryptedBlocks.push_back(des.encryptBlock(block));
    }

    return blocksToHexString(encryptedBlocks);
}

std::string desDecryptECB(const std::string& ciphertext, const std::string& key) {
    validateKey(key);
    DES des(key);

    std::vector<uint64_t> blocks = hexStringToBlocks(ciphertext);

    std::vector<uint64_t> decryptedBlocks;
    for (uint64_t block : blocks) {
        decryptedBlocks.push_back(des.decryptBlock(block));
    }

    std::string decryptedString = blocksToString(decryptedBlocks);

    return removePKCS5Padding(decryptedString);
}

std::string des3EncryptECB(
    const std::string& plaintext, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    std::string paddedPlaintext = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = stringToBlocks(paddedPlaintext);

    std::vector<uint64_t> encryptedBlocks;
    for (uint64_t block : blocks) {
        uint64_t encryptedBlock = des1.encryptBlock(block);
        encryptedBlock = des2.decryptBlock(encryptedBlock);
        encryptedBlock = des3.encryptBlock(encryptedBlock);
        encryptedBlocks.push_back(encryptedBlock);
    }

    return blocksToHexString(encryptedBlocks);
}

std::string des3DecryptECB(
    const std::string& ciphertext, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    std::vector<uint64_t> blocks = hexStringToBlocks(ciphertext);

    std::vector<uint64_t> decryptedBlocks;
    for (uint64_t block : blocks) {
        uint64_t decryptedBlock = des3.decryptBlock(block);
        decryptedBlock = des2.encryptBlock(decryptedBlock);
        decryptedBlock = des1.decryptBlock(decryptedBlock);
        decryptedBlocks.push_back(decryptedBlock);
    }

    std::string decryptedString = blocksToString(decryptedBlocks);

    return removePKCS5Padding(decryptedString);
}

std::string desEncryptCBC(const std::string& plaintext, const std::string& iv, const std::string& key) {
    validateKey(key);
    DES des(key);

    std::string paddedPlaintext = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = stringToBlocks(paddedPlaintext);

    uint64_t ivVec = hexStringToUint64(iv);

    std::vector<uint64_t> encryptedBlocks;
    uint64_t currentIV = ivVec;
    for (uint64_t block : blocks) {
        block ^= currentIV;
        uint64_t encryptedBlock = des.encryptBlock(block);
        encryptedBlocks.push_back(encryptedBlock);
        currentIV = encryptedBlock;
    }

    return blocksToHexString(encryptedBlocks);
}

std::string desDecryptCBC(const std::string& ciphertext, const std::string& iv, const std::string& key) {
    validateKey(key);
    DES des(key);

    std::vector<uint64_t> blocks = hexStringToBlocks(ciphertext);
    uint64_t ivVec = hexStringToUint64(iv);

    std::vector<uint64_t> decryptedBlocks;
    uint64_t currentIV = ivVec;
    for (uint64_t block : blocks) {
        uint64_t decryptedBlock = des.decryptBlock(block);
        decryptedBlock ^= currentIV;
        decryptedBlocks.push_back(decryptedBlock);
        currentIV = block; // Update IV to the current ciphertext block
    }

    std::string decryptedString = blocksToString(decryptedBlocks);

    return removePKCS5Padding(decryptedString);
}

std::string des3EncryptCBC(
    const std::string& plaintext,
    const std::string& iv, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    std::string paddedPlaintext = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = stringToBlocks(paddedPlaintext);

    uint64_t ivVec = hexStringToUint64(iv);

    std::vector<uint64_t> encryptedBlocks;
    uint64_t currentIV = ivVec;
    for (uint64_t block : blocks) {
        block ^= currentIV;

        uint64_t encryptedBlock = des1.encryptBlock(block);
        encryptedBlock = des2.decryptBlock(encryptedBlock);
        encryptedBlock = des3.encryptBlock(encryptedBlock);
        encryptedBlocks.push_back(encryptedBlock);

        currentIV = encryptedBlock;
    }

    return blocksToHexString(encryptedBlocks);
}

std::string des3DecryptCBC(
    const std::string& ciphertext,
    const std::string& iv, 
    const std::string& key1, 
    const std::string& key2, 
    const std::string& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    std::vector<uint64_t> blocks = hexStringToBlocks(ciphertext);
    uint64_t ivVec = hexStringToUint64(iv);

    std::vector<uint64_t> decryptedBlocks;
    uint64_t currentIV = ivVec;
    for (uint64_t block : blocks) {
        uint64_t decryptedBlock = des3.decryptBlock(block);
        decryptedBlock = des2.encryptBlock(decryptedBlock);
        decryptedBlock = des1.decryptBlock(decryptedBlock);

        decryptedBlock ^= currentIV;
        decryptedBlocks.push_back(decryptedBlock);
        currentIV = block; // Update IV to the current ciphertext block
    }

    std::string decryptedString = blocksToString(decryptedBlocks);

    return removePKCS5Padding(decryptedString);
}