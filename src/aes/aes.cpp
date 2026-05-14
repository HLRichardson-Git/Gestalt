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
#include "modes/modes.h"
#include "modes/gcm/gcm.h"

/*
 * Encrypts an arbitrarily sized input with AES_ECB.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param key  The 128, 192, or 256 bit key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes encryptAESECB(const SecureBytes& plaintext, const SecureBytes& key) {
    AES cipher(key);
    return encryptECB(plaintext, cipher);
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
 * @param plaintext  The plaintext as raw bytes.
 * @param iv   The initialization vector as raw bytes.
 * @param key  The 128, 192, or 256 bit key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes encryptAESCBC(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key) {
    AES cipher(key);
    return encryptCBC(plaintext, iv, cipher);
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

/*
 * Encrypts an arbitrarily sized input with AES_CBC.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param iv   The initialization vector as raw bytes.
 * @param key  The 128, 192, or 256 bit key as raw bytes.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes encryptAESCFB(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key) {
    AES cipher(key);
    return encryptCFB(plaintext, iv, cipher);
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
SecureBytes decryptAESCFB(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key) {
    AES cipher(key);
    return decryptCFB(ciphertext, iv, cipher);
}

/*
 * Encrypts an arbitrarily input with AES_CTR.
 *
 * @param plaintext The plaintext as raw bytes.
 * @param iv The number-used-once (nonce) in hex.
 * @param key The 128, 192, or 256 bit key in hex.
 * @result Encrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes encryptAESCTR(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key) {
	AES cipher(key);
    return encryptCTR(plaintext, iv, cipher);
}

/*
 * Decrypts an arbitrarily input with AES_CTR.
 *
 * @param ciphertext The ciphertext as raw bytes.
 * @param iv The number-used-once (nonce) in hex.
 * @param key The 128, 192, or 256 bit key in hex.
 * @result Decrypted bytes.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
SecureBytes decryptAESCTR(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key) {
    AES cipher(key);
    return decryptCTR(ciphertext, iv, cipher);
}

/*
 * Encrypts an arbitrarily sized input with AES_GCM, returning the ciphertext and authentication tag.
 *
 * @param plaintext  The plaintext as raw bytes.
 * @param iv         The initialization vector (12 bytes recommended).
 * @param key        The 128, 192, or 256 bit key as raw bytes.
 * @param aad        Additional authenticated data (authenticated but not encrypted).
 * @param tagLen     Length of the authentication tag in bytes (default 16).
 * @result GCMEncryptResult containing ciphertext and tag.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
GCMEncryptResult encryptAESGCM(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key, const SecureBytes& aad, size_t tagLen) {
    AES cipher(key);
    return encryptGCM(plaintext, iv, aad, tagLen, cipher);
}

/*
 * Decrypts an arbitrarily sized input with AES_GCM, verifying the authentication tag.
 *
 * @param ciphertext  The encrypted bytes.
 * @param iv          The initialization vector used during encryption.
 * @param key         The 128, 192, or 256 bit key as raw bytes.
 * @param tag         The authentication tag to verify.
 * @param aad         Additional authenticated data (must match what was used during encryption).
 * @result GCMDecryptResult containing plaintext and authenticated flag.
 *         If authentication fails, plaintext is empty and authenticated is false.
 * @throws std::invalid_argument if the key size is not 128, 192, or 256 bits.
 */
GCMDecryptResult decryptAESGCM(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key, const SecureBytes& tag, const SecureBytes& aad) {
    AES cipher(key);
    return decryptGCM(ciphertext, tag, iv, aad, cipher);
}
