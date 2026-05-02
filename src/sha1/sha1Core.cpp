/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha1Core.cpp
 *
 * This file contains the implementation of the SHA-1 (Secure Hash Algorithm 1) hashing function.
 * SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value, typically represented as a
 * 40-digit hexadecimal number. It is widely used in security applications and protocols, including TLS, SSL, SSH, and
 * IPsec.
 *
 * References:
 * - [1] "Secure Hash Standard (SHS)" by the National Institute of Standards and Technology (NIST)
 * - RFC 3174: US Secure Hash Algorithm 1 (SHA1) (https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf)
 * - [2] "Understanding Cryptography" by Christof Paar and Jan Pelzl
 */

#include "sha1Core.h"
#include "../tools/utils.h"


SHA1::SHA1() {
    // Constructor implementation, if needed
}

/*
 * Generates the SHA-1 hash value for the input string.
 *
 * @param in The input to be hashed.
 * @return The SHA-1 hash value as a SecureBytes object.
 */
SecureBytes SHA1::hash(const SecureBytes& in) {
    reset();
    SecureBytes padded = in;
    applySha1Padding(padded);

    for (size_t i = 0; i < padded.size(); i += 64) {
        uint32_t w[BLOCK_SIZE];

        // Fill SHA-1 block from the current 64-byte chunk
        fillBlock(padded, i, w);
        
        // Initialize hash value for this chunk
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int j = 0; j < 80; ++j) {
            uint32_t f = 0, k = 0;
            if (j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[j];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    return digest();
}

/*
 * Calculates the SHA-1 hash digest from the accumulated hash values.
 *
 * @return The SHA-1 hash digest as a SecureBytes object.
 */
SecureBytes SHA1::digest() {
    SecureBytes result(20);
    uint32_t vals[5] = { h0, h1, h2, h3, h4 };
    for (int i = 0; i < 5; ++i) {
        result[i * 4 + 0] = (vals[i] >> 24) & 0xFF;
        result[i * 4 + 1] = (vals[i] >> 16) & 0xFF;
        result[i * 4 + 2] = (vals[i] >>  8) & 0xFF;
        result[i * 4 + 3] = (vals[i]       ) & 0xFF;
    }
    return result;
}

/*
 * Resets the internal hash state to its initial values.
 *
 * See reference [1] for details.
 */
void SHA1::reset() {
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
    h4 = 0xc3d2e1f0;
}

/*
 * Fills a 512-bit block with the input message data.
 *
 * @param in The input from which data is filled into the block.
 * @param offset The byte offset into the input at which the current block starts.
 * @param w The output block array.
 */
void SHA1::fillBlock(const SecureBytes& in, std::size_t offset, uint32_t w[BLOCK_SIZE]) {
    for (int j = 0; j < 16; ++j) {
        w[j] = ((in[offset + j * 4 + 3] & 0xff)) |
               ((in[offset + j * 4 + 2] & 0xff) << 8) |
               ((in[offset + j * 4 + 1] & 0xff) << 16) |
               ((in[offset + j * 4 + 0] & 0xff) << 24);
    }
    for (int j = 16; j < 80; ++j) {
        uint32_t temp = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
        w[j] = (temp << 1) | (temp >> 31);
    }
}

/*
 * Applies SHA-1 padding to the input.
 *
 * @param in The input to which padding is applied.
 */
void SHA1::applySha1Padding(SecureBytes& in) {
    uint64_t messageLength = static_cast<uint64_t>(in.size()) * 8;

    // Add the '1' bit
    in.append(SecureBytes(1, 0x80));

    // Append '0' bits until the padded message length is 64 bits less than
    // a multiple of 512
    while ((in.size() % 64) != 56) {
        in.append(SecureBytes(1, 0x00));
    }

    // Append the length of the original message in bits as a 64-bit big-endian integer
    SecureBytes lenBytes(8);
    for (int i = 0; i < 8; ++i) {
        lenBytes[i] = static_cast<uint8_t>((messageLength >> ((7 - i) * 8)) & 0xFF);
    }
    in.append(lenBytes);
}