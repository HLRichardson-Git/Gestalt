/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2Core.cpp
 *
 */

#include "sha2Core.h"

#include <sstream>
#include <iomanip>

uint32_t ROTR(uint32_t n, uint32_t x) {
    return (x >> n) | (x << (32 - n));
}

uint32_t SHR(uint32_t n, uint32_t x) {
    return x >> n;
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t BSIG0(uint32_t x) {
    return ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x);
}

uint32_t BSIG1(uint32_t x) {
    return ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x);
}

uint32_t SSIG0(uint32_t x) {
    return ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x);
}

uint32_t SSIG1(uint32_t x) {
    return ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x);
}

void applySha2Padding(std::string& in) {
    size_t messageLength = in.length() * 8;

    // Add the '1' bit
    in += (char)0x80;

    // Append '0' bits until the padded message length is 64 bits less than 
    // a multiple of 512
    while ((in.length() % 64) != 56) {
        in += (char)0x00;
    }

    // Append the length of the original message in bits as a 64-bit big-endian
    // integer
    for (int i = 7; i >= 0; --i) {
        in += (char)((messageLength >> (i * 8)) & 0xFF);
    }
}

void fillBlock(std::string& in, uint32_t W[64]) {
    for (int j = 0; j < 16; ++j) {
        W[j] = ((in[j * 4 + 3] & 0xff)) |
               ((in[j * 4 + 2] & 0xff) << 8) |
               ((in[j * 4 + 1] & 0xff) << 16) |
               ((in[j * 4 + 0] & 0xff) << 24);
    }
    for (int j = 16; j < 64; ++j) {
        W[j] = SSIG1(W[j - 2]) + W[j - 7] + SSIG0(W[j - 15]) + W[j - 16];
    }
}

std::string hashSHA2TEMP(std::string& in) {
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    applySha2Padding(in);

    for (size_t i = 0; i < in.length(); i+=64) {
        uint32_t W[64];
        std::string chunk = in.substr(i, 64);
        fillBlock(chunk, W);

        // Initialize hash value for this chunk
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        for (size_t t = 0; t < 64; t++) {
            uint32_t T1 = h + BSIG1(e) + Ch(e, f, g) + K[t] + W[t];
            uint32_t T2 = BSIG0(a) + Maj(a, b, c);
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

    uint8_t hashValue[32];
    hashValue[0] = (H[0] >> 24) & 0xFF;
    hashValue[1] = (H[0] >> 16) & 0xFF;
    hashValue[2] = (H[0] >> 8) & 0xFF;
    hashValue[3] = H[0] & 0xFF;
    hashValue[4] = (H[1] >> 24) & 0xFF;
    hashValue[5] = (H[1] >> 16) & 0xFF;
    hashValue[6] = (H[1] >> 8) & 0xFF;
    hashValue[7] = H[1] & 0xFF;
    hashValue[8] = (H[2] >> 24) & 0xFF;
    hashValue[9] = (H[2] >> 16) & 0xFF;
    hashValue[10] = (H[2] >> 8) & 0xFF;
    hashValue[11] = H[2] & 0xFF;
    hashValue[12] = (H[3] >> 24) & 0xFF;
    hashValue[13] = (H[3] >> 16) & 0xFF;
    hashValue[14] = (H[3] >> 8) & 0xFF;
    hashValue[15] = H[3] & 0xFF;
    hashValue[16] = (H[4] >> 24) & 0xFF;
    hashValue[17] = (H[4] >> 16) & 0xFF;
    hashValue[18] = (H[4] >> 8) & 0xFF;
    hashValue[19] = H[4] & 0xFF;
    hashValue[20] = (H[5] >> 24) & 0xFF;
    hashValue[21] = (H[5] >> 16) & 0xFF;
    hashValue[22] = (H[5] >> 8) & 0xFF;
    hashValue[23] = H[5] & 0xFF;
    hashValue[24] = (H[6] >> 24) & 0xFF;
    hashValue[25] = (H[6] >> 16) & 0xFF;
    hashValue[26] = (H[6] >> 8) & 0xFF;
    hashValue[27] = H[6] & 0xFF;
    hashValue[28] = (H[7] >> 24) & 0xFF;
    hashValue[29] = (H[7] >> 16) & 0xFF;
    hashValue[30] = (H[7] >> 8) & 0xFF;
    hashValue[31] = H[7] & 0xFF;

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}