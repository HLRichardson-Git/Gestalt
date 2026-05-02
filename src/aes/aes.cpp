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

#include <gestalt/aes.h>
#include "aesCore.h"
#include "modes.h"

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
    return encryptECB(msg, cipher);
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
    return decryptECB(ciphertext, cipher);
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
    return encryptCBC(msg, iv, cipher);
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
    return decryptCBC(ciphertext, iv, cipher);
}