/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2.cpp
 *
 * This file contains the implementation of Gestalts SHA2 security functions.
 */

#include <climits>
#include <cstdint>

#include <gestalt/sha2.h>
#include "sha2Constants.h"

#define ROTR(n, x) ((x >> n) | (x << (32 - n)))
#define ROTR512(n, x) ((x >> n) | (x << (64 - n)))

#define SHR(n, x) (x >> n)
#define CH(x, y, z) ((x & y) ^ ((~x) & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

inline uint32_t BSIG0(uint32_t x) { return ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x); }
inline uint32_t BSIG1(uint32_t x) { return ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x); }
inline uint32_t SSIG0(uint32_t x) { return ROTR(7, x)  ^ ROTR(18, x) ^ SHR(3, x); }
inline uint32_t SSIG1(uint32_t x) { return ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x); }

inline uint64_t BSIG0(uint64_t x) { return ROTR512(28, x) ^ ROTR512(34, x) ^ ROTR512(39, x); }
inline uint64_t BSIG1(uint64_t x) { return ROTR512(14, x) ^ ROTR512(18, x) ^ ROTR512(41, x); }
inline uint64_t SSIG0(uint64_t x) { return ROTR512(1, x)  ^ ROTR512(8, x)  ^ SHR(7, x); }
inline uint64_t SSIG1(uint64_t x) { return ROTR512(19, x) ^ ROTR512(61, x) ^ SHR(6, x); }

bool isValidSHA2Length(uint64_t length) {
    return length >= 0 && length < ULLONG_MAX - 1;
}

SecureBytes applyPadding(const SecureBytes& in, size_t wordSize) {
    SecureBytes out = in;
    uint64_t bitLengthLow = static_cast<uint64_t>(in.size()) * 8;
    uint64_t bitLengthHigh = (wordSize == 4) ? 0 : (static_cast<uint64_t>(in.size()) >> 61);

    // Validate input length against SHA-2 bounds
    if (wordSize == 4 && !isValidSHA2Length(bitLengthLow))
        throw std::invalid_argument("Error: Given input for SHA256 family is larger than 0 <= length < 2^64.");
    if (wordSize == 8 && !isValidSHA2Length(bitLengthHigh))
        throw std::invalid_argument("Error: Given input for SHA512 family is out of bounds 0 <= length < 2^128.");

    out.append(SecureBytes(1, 0x80)); // append the '1' bit

    // Append zeros until reaching the message length boundary
    while ((out.size() % (wordSize * 16)) != 14 * wordSize) { // 14 * wordsize = wordSize * 16 - (wordSize * 2)
        out.append(SecureBytes(1, 0x00));
    }

    // Append message length
    if (wordSize == 8) { // Append high 64 bits if using SHA-512
        SecureBytes highLen(8);
        for (int i = 0; i < 8; ++i)
            highLen[i] = static_cast<uint8_t>((bitLengthHigh >> ((7 - i) * 8)) & 0xFF);
        out.append(highLen);
    }
    // Append low 64 bits in any case
    SecureBytes lowLen(8);
    for (int i = 0; i < 8; ++i)
        lowLen[i] = static_cast<uint8_t>((bitLengthLow >> ((7 - i) * 8)) & 0xFF);
    out.append(lowLen);

    return out;
}

/*
 * Fills block to be hashed by SHA2 function.
 * @tparam T Type of the word (uint32_t or uint64_t).
 * @tparam NumOfWords Number of words in the W array (64 for SHA-256, 80 for SHA-512).
 * @param in The padded input message.
 * @param offset The byte offset into the input at which the current block starts.
 * @param W The output word array to fill.
 */
template<typename T, int NumOfWords>
void fillBlock(const SecureBytes& in, std::size_t offset, T W[NumOfWords]) {
    size_t wordSize = sizeof(T);

    for (int i = 0; i < 16; ++i) {
        W[i] = 0;
        for (size_t j = 0; j < wordSize; j++) {
            W[i] |= ((static_cast<T>(in[offset + i * wordSize + j] & 0xFF)) << ((wordSize - 1 - j) * 8));
        }
    }

    for (int i = 16; i < NumOfWords; ++i) {
        W[i] = SSIG1(W[i - 2]) + W[i - 7] + SSIG0(W[i - 15]) + W[i - 16];
    }
}

/*
 * Computes SHA-2 hash for the input message.
 * @tparam T Type of the word (uint32_t or uint64_t).
 * @tparam NumOfWords Number of words in the W array (64 for SHA-256, 80 for SHA-512).
 * @tparam K Array of constants (K256 or K512).
 * @tparam HashSize Size of the hash output in bytes.
 * @param in The input message.
 * @param H Initial hash values.
 * @return The computed hash as a SecureBytes object.
 */
template<typename T, size_t NumOfWords, const std::array<T, NumOfWords>& K, size_t HashSize>
SecureBytes sha2(const SecureBytes& in, std::array<T, 8> H) {
    size_t wordSize = sizeof(T);
    size_t blockSize = (wordSize == 4 ? 64 : 128);
    SecureBytes msg = applyPadding(in, wordSize);

    for (size_t i = 0; i < msg.size(); i += blockSize) {
        T W[NumOfWords] = {0};
        fillBlock<T, NumOfWords>(msg, i, W);

        // Initialize hash value for this chunk
        T a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

        for (size_t t = 0; t < NumOfWords; t++) {
            T T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + W[t];
            T T2 = BSIG0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    SecureBytes result(HashSize);
    for (size_t i = 0; i < HashSize / wordSize; i++) {
        for (size_t j = 0; j < wordSize; j++) {
            result[i * wordSize + j] = (H[i] >> ((wordSize - 1 - j) * 8)) & 0xFF;
        }
    }

    // Handle special case that function call is SHA512_224
    // I agree its ugly
    if (wordSize == 8 && HashSize == 28) {
        for (int i = 0; i < 4; ++i) {
            result[24 + i] = static_cast<uint8_t>((H[3] >> (56 - i * 8)) & 0xFF);
        }
    }

    return result;
}

SecureBytes hashSHA224    (const SecureBytes& in) { return sha2<uint32_t, 64, K256, 28>(in, SHA_224_H); }
SecureBytes hashSHA256    (const SecureBytes& in) { return sha2<uint32_t, 64, K256, 32>(in, SHA_256_H); }
SecureBytes hashSHA384    (const SecureBytes& in) { return sha2<uint64_t, 80, K512, 48>(in, SHA_384_H); }
SecureBytes hashSHA512    (const SecureBytes& in) { return sha2<uint64_t, 80, K512, 64>(in, SHA_512_H); }
SecureBytes hashSHA512_224(const SecureBytes& in) { return sha2<uint64_t, 80, K512, 28>(in, SHA_512_224_H); }
SecureBytes hashSHA512_256(const SecureBytes& in) { return sha2<uint64_t, 80, K512, 32>(in, SHA_512_256_H); }