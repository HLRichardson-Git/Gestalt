/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * cbc.cpp
 *
 * Template definition and explicit instantiations for CBC (Cipher Block Chaining) mode of operation.
 */

#include "modes.h"
#include "aes/aesCore.h"
#include "des/desCore.h"

template<BlockCipher C>
SecureBytes encryptCBC(const SecureBytes& plaintext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    SecureBytes padded = applyPKCSPadding(plaintext, C::block_size);
    SecureBytes result(padded.size());

    std::array<uint8_t, C::block_size> currentIV;
    std::memcpy(currentIV.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < padded.size(); i += C::block_size) {
        std::array<uint8_t, C::block_size> block;
        std::memcpy(block.data(), padded.data() + i, C::block_size);

        for (size_t j = 0; j < C::block_size; j++)
            block[j] ^= currentIV[j];

        cipher.encryptBlock(block);
        std::memcpy(result.data() + i, block.data(), C::block_size);
        currentIV = block;
    }
    return result;
}

template<BlockCipher C>
SecureBytes decryptCBC(const SecureBytes& ciphertext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    SecureBytes result(ciphertext.size());

    std::array<uint8_t, C::block_size> currentIV;
    std::memcpy(currentIV.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < ciphertext.size(); i += C::block_size) {
        std::array<uint8_t, C::block_size> block;
        std::memcpy(block.data(), ciphertext.data() + i, C::block_size);

        std::array<uint8_t, C::block_size> nextIV = block;
        cipher.decryptBlock(block);

        for (size_t j = 0; j < C::block_size; j++)
            block[j] ^= currentIV[j];

        std::memcpy(result.data() + i, block.data(), C::block_size);
        currentIV = nextIV;
    }
    return removePKCSPadding(result, C::block_size);
}

template SecureBytes encryptCBC<AES>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes decryptCBC<AES>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes encryptCBC<DES>(const SecureBytes&, const SecureBytes&, DES&);
template SecureBytes decryptCBC<DES>(const SecureBytes&, const SecureBytes&, DES&);
