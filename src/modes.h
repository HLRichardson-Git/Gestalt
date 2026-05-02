/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * modes.h
 *
 * This file contains template implementations of block cipher modes of operation.
 * Any cipher class satisfying the BlockCipher concept can be used with these templates.
 *
 * The BlockCipher concept requires:
 *   - static constexpr size_t block_size
 *   - void encryptBlock(std::array<uint8_t, block_size>&)
 *   - void decryptBlock(std::array<uint8_t, block_size>&)
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <gestalt/secure_bytes.h>

template<typename T>
concept BlockCipher = requires(T c, std::array<uint8_t, T::block_size>& b) {
    { T::block_size } -> std::convertible_to<std::size_t>;
    { c.encryptBlock(b) } -> std::same_as<void>;
    { c.decryptBlock(b) } -> std::same_as<void>;
};

// ---------------------------------------------------------------------------
// Padding helpers (PKCS#7 / PKCS#5 — identical algorithm, parameterized by
// block size)
// ---------------------------------------------------------------------------

inline SecureBytes applyPKCSPadding(const SecureBytes& data, size_t blockSize) {
    size_t padLen = blockSize - (data.size() % blockSize);
    SecureBytes padded(data.size() + padLen);
    std::memcpy(padded.data(), data.data(), data.size());
    std::memset(padded.data() + data.size(), static_cast<uint8_t>(padLen), padLen);
    return padded;
}

inline SecureBytes removePKCSPadding(const SecureBytes& data, size_t blockSize) {
    if (data.empty() || data.size() % blockSize != 0)
        throw std::invalid_argument("Invalid ciphertext size");
    size_t padLen = data[data.size() - 1];
    if (padLen == 0 || padLen > blockSize)
        throw std::invalid_argument("Invalid PKCS padding");
    SecureBytes result(data.size() - padLen);
    std::memcpy(result.data(), data.data(), data.size() - padLen);
    return result;
}

// ---------------------------------------------------------------------------
// ECB
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CBC
// ---------------------------------------------------------------------------

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
