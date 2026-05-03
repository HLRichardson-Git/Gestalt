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
#include "modes/modes.h"

/*
 * Encrypts an arbitrarily sized input with DES_ECB.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param key        The 64-bit (8 byte) DES key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 8 bytes.
 */
SecureBytes encryptDESECB(const SecureBytes& plaintext, const SecureBytes& key) {
    validateKey(key);
    DES des(key);
    return encryptECB(plaintext, des);
}

/*
 * Decrypts an arbitrarily sized input with DES_ECB.
 *
 * @param ciphertext  The encrypted bytes.
 * @param key         The 64-bit (8 byte) DES key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if the key size is not 8 bytes.
 */
SecureBytes decryptDESECB(const SecureBytes& ciphertext, const SecureBytes& key) {
    validateKey(key);
    DES des(key);
    return decryptECB(ciphertext, des);
}

/*
 * Encrypts an arbitrarily sized input with 3DES_ECB using an encrypt-decrypt-encrypt (EDE) scheme.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param key1       The first 64-bit (8 byte) DES key as raw bytes.
 * @param key2       The second 64-bit (8 byte) DES key as raw bytes.
 * @param key3       The third 64-bit (8 byte) DES key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if any key is not 8 bytes or the key arrangement is invalid.
 */
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

    SecureBytes padded = applyPKCSPadding(plaintext, DES::block_size);
    SecureBytes result(padded.size());

    for (size_t i = 0; i < padded.size(); i += DES::block_size) {
        std::array<uint8_t, DES::block_size> block;
        std::memcpy(block.data(), padded.data() + i, DES::block_size);
        des1.encryptBlock(block);
        des2.decryptBlock(block);
        des3.encryptBlock(block);
        std::memcpy(result.data() + i, block.data(), DES::block_size);
    }
    return result;
}

/*
 * Decrypts an arbitrarily sized input with 3DES_ECB using a decrypt-encrypt-decrypt (DED) scheme.
 *
 * @param ciphertext  The encrypted bytes.
 * @param key1        The first 64-bit (8 byte) DES key as raw bytes.
 * @param key2        The second 64-bit (8 byte) DES key as raw bytes.
 * @param key3        The third 64-bit (8 byte) DES key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if any key is not 8 bytes or the key arrangement is invalid.
 */
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

    SecureBytes result(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += DES::block_size) {
        std::array<uint8_t, DES::block_size> block;
        std::memcpy(block.data(), ciphertext.data() + i, DES::block_size);
        des3.decryptBlock(block);
        des2.encryptBlock(block);
        des1.decryptBlock(block);
        std::memcpy(result.data() + i, block.data(), DES::block_size);
    }
    return removePKCSPadding(result, DES::block_size);
}

/*
 * Encrypts an arbitrarily sized input with DES_CBC.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param iv         The 64-bit (8 byte) initialization vector as raw bytes.
 * @param key        The 64-bit (8 byte) DES key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 8 bytes.
 */
SecureBytes encryptDESCBC(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key) {
    validateKey(key);
    DES des(key);
    return encryptCBC(plaintext, iv, des);
}

/*
 * Decrypts an arbitrarily sized input with DES_CBC.
 *
 * @param ciphertext  The encrypted bytes.
 * @param iv          The 64-bit (8 byte) initialization vector as raw bytes.
 * @param key         The 64-bit (8 byte) DES key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if the key size is not 8 bytes.
 */
SecureBytes decryptDESCBC(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key) {
    validateKey(key);
    DES des(key);
    return decryptCBC(ciphertext, iv, des);
}

/*
 * Encrypts an arbitrarily sized input with 3DES_CBC using an encrypt-decrypt-encrypt (EDE) scheme.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param iv         The 64-bit (8 byte) initialization vector as raw bytes.
 * @param key1       The first 64-bit (8 byte) DES key as raw bytes.
 * @param key2       The second 64-bit (8 byte) DES key as raw bytes.
 * @param key3       The third 64-bit (8 byte) DES key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if any key is not 8 bytes or the key arrangement is invalid.
 */
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

    if (iv.size() != DES::block_size)
        throw std::invalid_argument("IV size must be 8 bytes for DES");

    SecureBytes padded = applyPKCSPadding(plaintext, DES::block_size);
    SecureBytes result(padded.size());

    std::array<uint8_t, DES::block_size> currentIV;
    std::memcpy(currentIV.data(), iv.data(), DES::block_size);

    for (size_t i = 0; i < padded.size(); i += DES::block_size) {
        std::array<uint8_t, DES::block_size> block;
        std::memcpy(block.data(), padded.data() + i, DES::block_size);

        for (size_t j = 0; j < DES::block_size; j++)
            block[j] ^= currentIV[j];

        des1.encryptBlock(block);
        des2.decryptBlock(block);
        des3.encryptBlock(block);
        std::memcpy(result.data() + i, block.data(), DES::block_size);
        currentIV = block;
    }
    return result;
}

/*
 * Decrypts an arbitrarily sized input with 3DES_CBC using a decrypt-encrypt-decrypt (DED) scheme.
 *
 * @param ciphertext  The encrypted bytes.
 * @param iv          The 64-bit (8 byte) initialization vector as raw bytes.
 * @param key1        The first 64-bit (8 byte) DES key as raw bytes.
 * @param key2        The second 64-bit (8 byte) DES key as raw bytes.
 * @param key3        The third 64-bit (8 byte) DES key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if any key is not 8 bytes or the key arrangement is invalid.
 */
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

    if (iv.size() != DES::block_size)
        throw std::invalid_argument("IV size must be 8 bytes for DES");

    SecureBytes result(ciphertext.size());

    std::array<uint8_t, DES::block_size> currentIV;
    std::memcpy(currentIV.data(), iv.data(), DES::block_size);

    for (size_t i = 0; i < ciphertext.size(); i += DES::block_size) {
        std::array<uint8_t, DES::block_size> block;
        std::memcpy(block.data(), ciphertext.data() + i, DES::block_size);

        std::array<uint8_t, DES::block_size> nextIV = block;
        des3.decryptBlock(block);
        des2.encryptBlock(block);
        des1.decryptBlock(block);

        for (size_t j = 0; j < DES::block_size; j++)
            block[j] ^= currentIV[j];

        std::memcpy(result.data() + i, block.data(), DES::block_size);
        currentIV = nextIV;
    }
    return removePKCSPadding(result, DES::block_size);
}

/*
 * Encrypts an arbitrarily sized input with DES_CTR.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param iv         The 64-bit (8 byte) initialization vector as raw bytes.
 * @param key        The 64-bit (8 byte) DES key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 8 bytes.
 */
SecureBytes encryptDESCTR(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key) {
    validateKey(key);
    DES des(key);
    return encryptCTR(plaintext, iv, des);
}

/*
 * Decrypts an arbitrarily sized input with DES_CTR.
 *
 * @param ciphertext  The encrypted bytes.
 * @param iv          The 64-bit (8 byte) initialization vector as raw bytes.
 * @param key         The 64-bit (8 byte) DES key as raw bytes.
 * @result Decrypted plaintext bytes.
 * @throws std::invalid_argument if the key size is not 8 bytes.
 */
SecureBytes decryptDESCTR(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key) {
    validateKey(key);
    DES des(key);
    return decryptCTR(ciphertext, iv, des);
}
