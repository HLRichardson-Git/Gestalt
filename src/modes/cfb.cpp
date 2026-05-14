/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * cfb.cpp
 *
 * Template definition and explicit instantiations for CFB (Cipher Feeback) mode of operation.
 */

#include "modes.h"
#include "aes/aesCore.h"
#include "des/desCore.h"

template<BlockCipher C>
SecureBytes encryptCFB(const SecureBytes& plaintext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    SecureBytes result(plaintext.size());

    std::array<uint8_t, C::block_size> keystream;
    std::memcpy(keystream.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < plaintext.size(); i += C::block_size) {
        std::array<uint8_t, C::block_size> block;
        std::memcpy(block.data(), plaintext.data() + i, C::block_size);

        cipher.encryptBlock(keystream);

        for (size_t j = 0; j < C::block_size; j++)
            keystream[j] ^= block[j];

        std::memcpy(result.data() + i, keystream.data(), C::block_size);
    }
    return result;
}

template<BlockCipher C>
SecureBytes decryptCFB(const SecureBytes& ciphertext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    SecureBytes result(ciphertext.size());

    std::array<uint8_t, C::block_size> keystream;
    std::memcpy(keystream.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < ciphertext.size(); i += C::block_size) {
        std::array<uint8_t, C::block_size> block;
        std::memcpy(block.data(), ciphertext.data() + i, C::block_size);

        cipher.encryptBlock(keystream);

        for (size_t j = 0; j < C::block_size; j++)
            keystream[j] ^= block[j];

        std::memcpy(result.data() + i, keystream.data(), C::block_size);
        keystream = block;  // feedback is the ciphertext block, not the recovered plaintext
    }
    return result;
}

template SecureBytes encryptCFB<AES>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes decryptCFB<AES>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes encryptCFB<DES>(const SecureBytes&, const SecureBytes&, DES&);
template SecureBytes decryptCFB<DES>(const SecureBytes&, const SecureBytes&, DES&);
