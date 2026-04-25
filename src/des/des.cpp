/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.cpp
 *
 * This file contains the implementation of Gestalts DES & 3DES security functions.
 */

#include <gestalt/des.h>
#include "des/desCore.h"

SecureBytes encryptDESECB(const SecureBytes& plaintext, const SecureBytes& key) {
    validateKey(key);
    DES des(key);

    SecureBytes padded = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = bytesToBlocks(padded);

    std::vector<uint64_t> encryptedBlocks;
    for (uint64_t block : blocks)
        encryptedBlocks.push_back(des.encryptBlock(block));

    return blocksToBytes(encryptedBlocks);
}

SecureBytes decryptDESECB(const SecureBytes& ciphertext, const SecureBytes& key) {
    validateKey(key);
    DES des(key);

    std::vector<uint64_t> blocks = bytesToBlocks(ciphertext);

    std::vector<uint64_t> decryptedBlocks;
    for (uint64_t block : blocks)
        decryptedBlocks.push_back(des.decryptBlock(block));

    return removePKCS5Padding(blocksToBytes(decryptedBlocks));
}

SecureBytes encrypt3DESECB(
    const SecureBytes& plaintext,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    SecureBytes padded = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = bytesToBlocks(padded);

    std::vector<uint64_t> encryptedBlocks;
    for (uint64_t block : blocks) {
        uint64_t encryptedBlock = des1.encryptBlock(block);
        encryptedBlock = des2.decryptBlock(encryptedBlock);
        encryptedBlock = des3.encryptBlock(encryptedBlock);
        encryptedBlocks.push_back(encryptedBlock);
    }

    return blocksToBytes(encryptedBlocks);
}

SecureBytes decrypt3DESECB(
    const SecureBytes& ciphertext,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    std::vector<uint64_t> blocks = bytesToBlocks(ciphertext);

    std::vector<uint64_t> decryptedBlocks;
    for (uint64_t block : blocks) {
        uint64_t decryptedBlock = des3.decryptBlock(block);
        decryptedBlock = des2.encryptBlock(decryptedBlock);
        decryptedBlock = des1.decryptBlock(decryptedBlock);
        decryptedBlocks.push_back(decryptedBlock);
    }

    return removePKCS5Padding(blocksToBytes(decryptedBlocks));
}

SecureBytes encryptDESCBC(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key) {
    validateKey(key);
    DES des(key);

    SecureBytes padded = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = bytesToBlocks(padded);

    std::vector<uint64_t> encryptedBlocks;
    uint64_t currentIV = bytesToUint64(iv);
    for (uint64_t block : blocks) {
        block ^= currentIV;
        uint64_t encryptedBlock = des.encryptBlock(block);
        encryptedBlocks.push_back(encryptedBlock);
        currentIV = encryptedBlock;
    }

    return blocksToBytes(encryptedBlocks);
}

SecureBytes decryptDESCBC(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key) {
    validateKey(key);
    DES des(key);

    std::vector<uint64_t> blocks = bytesToBlocks(ciphertext);

    std::vector<uint64_t> decryptedBlocks;
    uint64_t currentIV = bytesToUint64(iv);
    for (uint64_t block : blocks) {
        uint64_t decryptedBlock = des.decryptBlock(block);
        decryptedBlock ^= currentIV;
        decryptedBlocks.push_back(decryptedBlock);
        currentIV = block;
    }

    return removePKCS5Padding(blocksToBytes(decryptedBlocks));
}

SecureBytes encrypt3DESCBC(
    const SecureBytes& plaintext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    SecureBytes padded = applyPCKS5Padding(plaintext);
    std::vector<uint64_t> blocks = bytesToBlocks(padded);

    std::vector<uint64_t> encryptedBlocks;
    uint64_t currentIV = bytesToUint64(iv);
    for (uint64_t block : blocks) {
        block ^= currentIV;

        uint64_t encryptedBlock = des1.encryptBlock(block);
        encryptedBlock = des2.decryptBlock(encryptedBlock);
        encryptedBlock = des3.encryptBlock(encryptedBlock);
        encryptedBlocks.push_back(encryptedBlock);

        currentIV = encryptedBlock;
    }

    return blocksToBytes(encryptedBlocks);
}

SecureBytes decrypt3DESCBC(
    const SecureBytes& ciphertext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
) {
    validateKeys(key1, key2, key3);
    DES des1(key1);
    DES des2(key2);
    DES des3(key3);

    std::vector<uint64_t> blocks = bytesToBlocks(ciphertext);

    std::vector<uint64_t> decryptedBlocks;
    uint64_t currentIV = bytesToUint64(iv);
    for (uint64_t block : blocks) {
        uint64_t decryptedBlock = des3.decryptBlock(block);
        decryptedBlock = des2.encryptBlock(decryptedBlock);
        decryptedBlock = des1.decryptBlock(decryptedBlock);

        decryptedBlock ^= currentIV;
        decryptedBlocks.push_back(decryptedBlock);
        currentIV = block;
    }

    return removePKCS5Padding(blocksToBytes(decryptedBlocks));
}