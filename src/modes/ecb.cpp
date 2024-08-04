/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecb.cpp
 *
 * This file contains the implementation of ECB (Electronic Codebook) mode encryption and decryption functions.
 * It includes functions to encrypt and decrypt data using ECB mode with various block ciphers.
 * 
 * References:
 * - NIST Special Publication SP800-38A: "Recommendation for Block Cipher Modes of Operation" (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 */

#include "modes.h"
#include <iomanip>
#include <sstream>

#include "../../tools/utils.h"
#include "../aes/aesCore.h"
//#include <gestalt/des.h>

/*
 * Electronic Codebook (ECB) Encryption In-Place:
 * 
 * The Electronic Codebook (ECB) mode is a confidentiality mode that features, for a given key,
 * the assignment of a fixed ciphertext block to each plaintext block, analogous to the assignment of
 * code words in a codebook.
 *
 * ECB Encryption: msg = encryptBlock(msg + blockIndex) blockIndex = 0, 16, ..., n
 *
 * In ECB encryption, the forward cipher function is applied directly and independently to each
 * block of the plaintext. The resulting sequence of output blocks is the ciphertext.
 *
 * ECB Encryption:
 *   Input:  Plaintext msg, key K
 *   Output: Ciphertext msg
 *
 * In ECB encryption, multiple forward cipher functions can be computed in parallel.
 */
template<
    typename BlockCipher, 
    typename BlockType, 
    size_t BlockSize, 
    void (BlockCipher::*encryptBlock)(BlockType&), 
    std::string(*paddingFunc)(const std::string&), 
    std::vector<BlockType>(*convertToBlocks)(const std::string&), 
    std::string(*blocksToHexString)(const std::vector<BlockType>&)
>
std::string encryptECB(std::string& msg, std::string key) {
    BlockCipher cipher(key);

    std::string paddedPlaintext = paddingFunc(msg);
    std::vector<BlockType> blocks = convertToBlocks(paddedPlaintext);

    std::vector<BlockType> encryptedBlocks;
    for (BlockType& block : blocks) {
        cipher.encryptBlock(block);
        encryptedBlocks.push_back(block);
    }

    return blocksToHexString(encryptedBlocks);
}

/*
 * Electronic Codebook (ECB) Decryption In-Place:
 * 
 * The Electronic Codebook (ECB) mode is a confidentiality mode that features, for a given key,
 * the assignment of a fixed ciphertext block to each plaintext block, analogous to the assignment of
 * code words in a codebook.
 *
 * ECB Decryption: msg = decryptBlock(msg + blockIndex) for blockIndex = 0, 16, ..., n.
 *
 * In ECB decryption, the inverse cipher function is applied directly and independently to each
 * block of the ciphertext. The resulting sequence of output blocks is the plaintext.
 *
 * ECB Decryption:
 *   Input:  Ciphertext msg, key K
 *   Output: Plaintext msg
 *
 * In ECB decryption, multiple inverse cipher functions can be computed in parallel.
 */
template<
    typename BlockCipher, 
    typename BlockType, 
    size_t BlockSize, 
    void (BlockCipher::*decryptBlock)(BlockType&), 
    std::string(*paddingFunc)(const std::string&), 
    std::vector<BlockType>(*convertToBlocks)(const std::string&), 
    std::string(*blocksToBytesString)(const std::vector<BlockType>&)
>
std::string decryptECB(std::string& hexMsg, std::string key) {
    BlockCipher cipher(key);

    std::vector<BlockType> blocks = convertToBlocks(fromHex(hexMsg));

    std::vector<BlockType> decryptedBlocks;
    for (BlockType& block : blocks) {
        cipher.decryptBlock(block);
        decryptedBlocks.push_back(block);
    }

    std::string decryptedMessage = blocksToBytesString(decryptedBlocks);


    return paddingFunc(decryptedMessage);
}

template std::string encryptECB<
    AES, 
    aesBlock, 
    AES_BLOCK_SIZE, 
    &AES::encryptBlock, 
    applyPKCS7Padding, 
    convertToAESBlocks, 
    aesBlocksToHexString
>(std::string&, std::string);

template std::string decryptECB<
    AES, 
    aesBlock, 
    AES_BLOCK_SIZE, 
    &AES::decryptBlock, 
    removePKCS7Padding, 
    convertToAESBlocks, 
    aesBlocksToBytesString
>(std::string&, std::string);

//template std::string encryptECB<DES, uint64_t, 8, applyPKCS5Padding>(std::string&, std::string, function<DES, uint64_t>);