/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ctr.cpp
 *
 * Template definition and explicit instantiations for CTR (Counter) mode of operation.
 */

#include "modes.h"
#include "aes/aesCore.h"
#include "des/desCore.h"

template<BlockCipher C>
SecureBytes encryptCTR(const SecureBytes& plaintext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    size_t msgLen = plaintext.size();
    SecureBytes result(msgLen);

    std::array<uint8_t, C::block_size> counter;
    std::memcpy(counter.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < msgLen; i += C::block_size) {
        std::array<uint8_t, C::block_size> keystream = counter;
        cipher.encryptBlock(keystream);  // Encrypt counter

        // XOR keystream with plaintext chunk
        size_t blockLen = std::min(C::block_size, msgLen - i);
        for (size_t j = 0; j < blockLen; j++)
            result[i + j] = plaintext[i + j] ^ keystream[j];

        // Increment counter
        for (int k = C::block_size - 1; k >= 0; k--)
            if (++counter[k]) break;
    }

    return result;
}

template<BlockCipher C>
SecureBytes decryptCTR(const SecureBytes& ciphertext, const SecureBytes& iv, C& cipher) {
    // Decrypting in CTR mode is the same as encrypting
    return encryptCTR(ciphertext, iv, cipher);
}

template SecureBytes encryptCTR<AES>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes decryptCTR<AES>(const SecureBytes&, const SecureBytes&, AES&);
//template SecureBytes encryptCBC<DES>(const SecureBytes&, const SecureBytes&, DES&);
//template SecureBytes decryptCBC<DES>(const SecureBytes&, const SecureBytes&, DES&);
