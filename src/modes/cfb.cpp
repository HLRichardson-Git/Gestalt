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
//template SecureBytes encryptCFB<DES>(const SecureBytes&, const SecureBytes&, DES&);
//template SecureBytes decryptCFB<DES>(const SecureBytes&, const SecureBytes&, DES&);

// CFB-s: generic byte-aligned sub-block variant (SegmentBits must be a multiple of 8
// and less than the cipher block size in bits)
template<BlockCipher C, size_t SegmentBits>
SecureBytes encryptCFBs(const SecureBytes& plaintext, const SecureBytes& iv, C& cipher) {
    static_assert(SegmentBits % 8 == 0, "SegmentBits must be a multiple of 8");
    static_assert(SegmentBits > 0, "SegmentBits must be > 0");

    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    constexpr size_t segBytes = SegmentBits / 8;
    const size_t msgLen = plaintext.size();
    SecureBytes result(msgLen);

    std::array<uint8_t, C::block_size> sr;
    std::memcpy(sr.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < msgLen; i += segBytes) {
        std::array<uint8_t, C::block_size> keystream = sr;
        cipher.encryptBlock(keystream);

        size_t chunkLen = std::min(segBytes, msgLen - i);
        for (size_t j = 0; j < chunkLen; j++)
            result[i + j] = keystream[j] ^ plaintext[i + j];

        // Shift SR left by chunkLen bytes, append ciphertext bytes on the right
        std::memmove(sr.data(), sr.data() + chunkLen, C::block_size - chunkLen);
        std::memcpy(sr.data() + C::block_size - chunkLen, result.data() + i, chunkLen);
    }
    return result;
}

template<BlockCipher C, size_t SegmentBits>
SecureBytes decryptCFBs(const SecureBytes& ciphertext, const SecureBytes& iv, C& cipher) {
    static_assert(SegmentBits % 8 == 0, "SegmentBits must be a multiple of 8");
    static_assert(SegmentBits > 0, "SegmentBits must be > 0");

    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    constexpr size_t segBytes = SegmentBits / 8;
    const size_t msgLen = ciphertext.size();
    SecureBytes result(msgLen);

    std::array<uint8_t, C::block_size> sr;
    std::memcpy(sr.data(), iv.data(), C::block_size);

    for (size_t i = 0; i < msgLen; i += segBytes) {
        std::array<uint8_t, C::block_size> keystream = sr;
        cipher.encryptBlock(keystream);

        size_t chunkLen = std::min(segBytes, msgLen - i);
        for (size_t j = 0; j < chunkLen; j++)
            result[i + j] = keystream[j] ^ ciphertext[i + j];

        // SR feedback is always the ciphertext input, not the recovered plaintext
        std::memmove(sr.data(), sr.data() + chunkLen, C::block_size - chunkLen);
        std::memcpy(sr.data() + C::block_size - chunkLen, ciphertext.data() + i, chunkLen);
    }
    return result;
}

// CFB1: 1-bit segment CFB. Processes plaintext one bit at a time (MSB first).
template<BlockCipher C>
SecureBytes encryptCFB1(const SecureBytes& plaintext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    const size_t msgBits = plaintext.size() * 8;
    SecureBytes result(plaintext.size());

    std::array<uint8_t, C::block_size> sr;
    std::memcpy(sr.data(), iv.data(), C::block_size);

    for (size_t b = 0; b < msgBits; b++) {
        std::array<uint8_t, C::block_size> keystream = sr;
        cipher.encryptBlock(keystream);

        uint8_t ksBit = (keystream[0] >> 7) & 1;
        uint8_t ptBit = (plaintext[b / 8] >> (7 - (b % 8))) & 1;
        uint8_t ctBit = ksBit ^ ptBit;

        result[b / 8] |= (ctBit << (7 - (b % 8)));

        // Shift SR left by 1 bit, append ciphertext bit to LSB
        for (size_t k = 0; k < C::block_size - 1; k++)
            sr[k] = (sr[k] << 1) | (sr[k + 1] >> 7);
        sr[C::block_size - 1] = (sr[C::block_size - 1] << 1) | ctBit;
    }
    return result;
}

template<BlockCipher C>
SecureBytes decryptCFB1(const SecureBytes& ciphertext, const SecureBytes& iv, C& cipher) {
    if (iv.size() != C::block_size)
        throw std::invalid_argument("IV size must match cipher block size");

    const size_t msgBits = ciphertext.size() * 8;
    SecureBytes result(ciphertext.size());

    std::array<uint8_t, C::block_size> sr;
    std::memcpy(sr.data(), iv.data(), C::block_size);

    for (size_t b = 0; b < msgBits; b++) {
        std::array<uint8_t, C::block_size> keystream = sr;
        cipher.encryptBlock(keystream);

        uint8_t ksBit = (keystream[0] >> 7) & 1;
        uint8_t ctBit = (ciphertext[b / 8] >> (7 - (b % 8))) & 1;
        uint8_t ptBit = ksBit ^ ctBit;

        result[b / 8] |= (ptBit << (7 - (b % 8)));

        // SR feedback is always the ciphertext bit
        for (size_t k = 0; k < C::block_size - 1; k++)
            sr[k] = (sr[k] << 1) | (sr[k + 1] >> 7);
        sr[C::block_size - 1] = (sr[C::block_size - 1] << 1) | ctBit;
    }
    return result;
}

template SecureBytes encryptCFBs<AES, 8>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes decryptCFBs<AES, 8>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes encryptCFBs<AES, 64>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes decryptCFBs<AES, 64>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes encryptCFB1<AES>(const SecureBytes&, const SecureBytes&, AES&);
template SecureBytes decryptCFB1<AES>(const SecureBytes&, const SecureBytes&, AES&);
