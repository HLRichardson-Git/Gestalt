/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * chacha.cpp
 *
 * This file contains the implementation of Gestalts ChaCha security functions.
 */

#include <gestalt/chacha.h>
#include "chachaCore.h"

SecureBytes encryptChaCha20(const SecureBytes& plaintext, const SecureBytes& key, const SecureBytes& nonce, const uint32_t& counter) {
    ChaCha cipher(key, nonce, counter);
    SecureBytes ciphertext(plaintext.size());
    size_t offset = 0;
    while (offset < plaintext.size()) {
        std::array<uint32_t, 16> block = cipher.chacha20_block();
        // serialize block to bytes, XOR with input chunk
        size_t chunk = std::min<size_t>(64, plaintext.size() - offset);
        for (size_t i = 0; i < chunk; ++i)
            ciphertext[offset + i] = plaintext[offset + i] ^ reinterpret_cast<uint8_t*>(block.data())[i];
        offset += chunk;
    }
    return ciphertext;
}

SecureBytes decryptChaCha20(const SecureBytes& ciphertext, const SecureBytes& key, const SecureBytes& nonce, const uint32_t& counter) {
    return encryptChaCha20(ciphertext, key, nonce, counter);
}
