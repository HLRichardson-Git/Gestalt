/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * gcm.cpp
 *
 * Template definition and explicit instantiations for GCM (Galois/Counter Mode) mode of operation.
 */

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "modes/modes.h"
#include "modes/gcm/gcm.h"
#include "aes/aesCore.h"

// GF(2^128) multiplication per NIST SP 800-38D Algorithm 1.
void ghashMultiply(std::array<uint8_t, 16>& X, const std::array<uint8_t, 16>& H) {
    std::array<uint8_t, 16> Z = {};
    std::array<uint8_t, 16> V = H;

    for (int i = 0; i < 128; i++) {
        if (X[i / 8] & (0x80 >> (i % 8))) {    // bit i of X (MSB-first within each byte)
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }
        bool lsb = V[15] & 1;
        for (int j = 15; j > 0; j--)
            V[j] = (V[j] >> 1) | (V[j - 1] << 7);
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xE1;
    }
    X = Z;
}

// Computes GHASH_H(aad, data) per NIST SP 800-38D.
std::array<uint8_t, 16> ghash(const std::array<uint8_t, 16>& H, const SecureBytes& aad, const SecureBytes& data) {
    std::array<uint8_t, 16> X = {};

    auto processBlocks = [&](const SecureBytes& input) {
        for (size_t i = 0; i < input.size(); i += 16) {
            std::array<uint8_t, 16> block = {};
            size_t len = std::min<size_t>(16, input.size() - i);
            std::memcpy(block.data(), input.data() + i, len);
            for (int j = 0; j < 16; j++) X[j] ^= block[j];
            ghashMultiply(X, H);
        }
    };

    if (!aad.empty()) processBlocks(aad);
    if (!data.empty()) processBlocks(data);

    // Length block: [len(aad) in bits]_64 || [len(data) in bits]_64, big-endian
    std::array<uint8_t, 16> lenBlock = {};
    uint64_t aadBits  = static_cast<uint64_t>(aad.size())  * 8;
    uint64_t dataBits = static_cast<uint64_t>(data.size()) * 8;
    for (int i = 7; i >= 0; i--) {
        lenBlock[i]     = aadBits  & 0xFF;  aadBits  >>= 8;
        lenBlock[8 + i] = dataBits & 0xFF;  dataBits >>= 8;
    }
    for (int j = 0; j < 16; j++) X[j] ^= lenBlock[j];
    ghashMultiply(X, H);

    return X;
}

// Increments the last 4 bytes of a 128-bit counter block.
void inc32(std::array<uint8_t, 16>& ctr) {
    for (int k = 15; k >= 12; k--)
        if (++ctr[k]) break;
}

template<BlockCipher C>
GCMEncryptResult encryptGCM(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& aad, size_t tagLen, C& cipher) {
    // 1. Generate GHASH subkey H = E(K, 0^128)
    std::array<uint8_t, 16> H = {};
    cipher.encryptBlock(H);

    // 2. Compute J0 (initial counter block)
    //    96-bit IV: J0 = IV || 0x00000001
    //    other:     J0 = GHASH(H, {}, IV)
    std::array<uint8_t, 16> j0 = {};
    if (iv.size() == 12) {
        std::memcpy(j0.data(), iv.data(), 12);
        j0[15] = 0x01;
    } else {
        j0 = ghash(H, SecureBytes{}, iv);
    }

    /*
     * 3. CTR encrypt starting at inc32(J0)
     *    We can't reuse the encryptCTR since it increments the full 128-bit counter
     *    while GCM only increments the last 4 bytes of the 128-bit counter.
    */
    std::array<uint8_t, 16> ctr = j0;
    inc32(ctr);

    size_t msgLen = plaintext.size();
    SecureBytes ciphertext(msgLen);
    for (size_t i = 0; i < msgLen; i += C::block_size) {
        std::array<uint8_t, 16> keystream = ctr;
        cipher.encryptBlock(keystream);
        size_t blockLen = std::min(C::block_size, msgLen - i);
        for (size_t j = 0; j < blockLen; j++)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        inc32(ctr);
    }

    // 4. Compute authentication tag: T = E(K, J0) XOR GHASH(H, aad, ciphertext)
    auto S = ghash(H, aad, ciphertext);
    std::array<uint8_t, 16> ej0 = j0;
    cipher.encryptBlock(ej0);

    SecureBytes tag(tagLen);
    for (size_t i = 0; i < tagLen; i++)
        tag[i] = ej0[i] ^ S[i];

    return GCMEncryptResult{std::move(ciphertext), std::move(tag)};
}

template<BlockCipher C>
GCMDecryptResult decryptGCM(const SecureBytes& ciphertext, const SecureBytes& tag, const SecureBytes& iv, const SecureBytes& aad, C& cipher) {
    // 1. Generate GHASH subkey H = E(K, 0^128)
    std::array<uint8_t, 16> H = {};
    cipher.encryptBlock(H);

    // 2. Compute J0
    std::array<uint8_t, 16> j0 = {};
    if (iv.size() == 12) {
        std::memcpy(j0.data(), iv.data(), 12);
        j0[15] = 0x01;
    } else {
        j0 = ghash(H, SecureBytes{}, iv);
    }

    // 3. Verify tag before decrypting (constant-time comparison)
    auto S = ghash(H, aad, ciphertext);
    std::array<uint8_t, 16> ej0 = j0;
    cipher.encryptBlock(ej0);

    uint8_t diff = 0;
    for (size_t i = 0; i < tag.size(); i++)
        diff |= tag[i] ^ (ej0[i] ^ S[i]);

    if (diff != 0)
        return GCMDecryptResult{SecureBytes{}, false};

    /*
     * 4. CTR decrypt starting at inc32(J0)
     *    We can't reuse the decryptCTR since it increments the full 128-bit counter
     *    while GCM only increments the last 4 bytes of the 128-bit counter.
    */
    std::array<uint8_t, 16> ctr = j0;
    inc32(ctr);

    size_t msgLen = ciphertext.size();
    SecureBytes plaintext(msgLen);
    for (size_t i = 0; i < msgLen; i += C::block_size) {
        std::array<uint8_t, 16> keystream = ctr;
        cipher.encryptBlock(keystream);
        size_t blockLen = std::min(C::block_size, msgLen - i);
        for (size_t j = 0; j < blockLen; j++)
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        inc32(ctr);
    }

    return GCMDecryptResult{std::move(plaintext), true};
}

template GCMEncryptResult encryptGCM<AES>(const SecureBytes&, const SecureBytes&, const SecureBytes&, size_t, AES&);
template GCMDecryptResult decryptGCM<AES>(const SecureBytes&, const SecureBytes&, const SecureBytes&, const SecureBytes&, AES&);
