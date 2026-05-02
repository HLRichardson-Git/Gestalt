/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * modes.h
 *
 * Defines the BlockCipher concept, shared padding utilities, and declarations
 * for the template mode-of-operation functions.
 *
 * Template definitions are in individual source files.
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

// ECB
template<BlockCipher C> SecureBytes encryptECB(const SecureBytes& plaintext, C& cipher);
template<BlockCipher C> SecureBytes decryptECB(const SecureBytes& ciphertext, C& cipher);

// CBC
template<BlockCipher C> SecureBytes encryptCBC(const SecureBytes& plaintext, const SecureBytes& iv, C& cipher);
template<BlockCipher C> SecureBytes decryptCBC(const SecureBytes& ciphertext, const SecureBytes& iv, C& cipher);
