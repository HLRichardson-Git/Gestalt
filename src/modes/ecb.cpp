/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecb.cpp
 *
 * Template definition and explicit instantiations for ECB (Electronic Codebook) mode of operation.
 */

#include "modes.h"
#include "aes/aesCore.h"
#include "des/desCore.h"

template<BlockCipher C>
SecureBytes encryptECB(const SecureBytes& plaintext, C& cipher) {
    SecureBytes padded = applyPKCSPadding(plaintext, C::block_size);
    SecureBytes result(padded.size());

    for (size_t i = 0; i < padded.size(); i += C::block_size) {
        std::array<uint8_t, C::block_size> block;
        std::memcpy(block.data(), padded.data() + i, C::block_size);
        cipher.encryptBlock(block);
        std::memcpy(result.data() + i, block.data(), C::block_size);
    }
    return result;
}

template<BlockCipher C>
SecureBytes decryptECB(const SecureBytes& ciphertext, C& cipher) {
    SecureBytes result(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += C::block_size) {
        std::array<uint8_t, C::block_size> block;
        std::memcpy(block.data(), ciphertext.data() + i, C::block_size);
        cipher.decryptBlock(block);
        std::memcpy(result.data() + i, block.data(), C::block_size);
    }
    return removePKCSPadding(result, C::block_size);
}

template SecureBytes encryptECB<AES>(const SecureBytes&, AES&);
template SecureBytes decryptECB<AES>(const SecureBytes&, AES&);
template SecureBytes encryptECB<DES>(const SecureBytes&, DES&);
template SecureBytes decryptECB<DES>(const SecureBytes&, DES&);
