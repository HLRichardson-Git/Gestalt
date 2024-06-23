/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2.cpp
 *
 * This file contains the implementation of Gestalts SHA2 security functions.
 */

#include <gestalt/sha2.h>

#include <sstream>
#include <iomanip>

#define ROTR(n, x) ((x >> n) | (x << (32 - n)))
#define SHR(n, x) (x >> n)
#define CH(x, y, z) ((x & y) ^ ((~x) & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x) (ROTR(2, x)  ^ ROTR(13, x) ^ ROTR(22, x))
#define BSIG1(x) (ROTR(6, x)  ^ ROTR(11, x) ^ ROTR(25, x))
#define SSIG0(x) (ROTR(7, x)  ^ ROTR(18, x) ^ SHR(3, x))
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

#define ROTR512(n, x) ((x >> n) | (x << (64 - n)))
#define BSIG5120(x) (ROTR512(28, x) ^ ROTR512(34, x) ^ ROTR512(39, x))
#define BSIG5121(x) (ROTR512(14, x) ^ ROTR512(18, x) ^ ROTR512(41, x))
#define SSIG5120(x) (ROTR512(1, x)  ^ ROTR512(8, x)  ^ SHR(7, x))
#define SSIG5121(x) (ROTR512(19, x) ^ ROTR512(61, x) ^ SHR(6, x))

const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint64_t K512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

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

void applySha512Padding(std::string& in) {
    size_t messageLength = in.length() * 8;

    // Add the '1' bit
    in += (char)0x80;

    // Append '0' bits until the padded message length is 128 bits less than 
    // a multiple of 1024
    while ((in.length() % 128) != 120) {
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

void fillBlock512(std::string& in, uint64_t W[80]) {
    for (int j = 0; j < 16; ++j) {
        W[j] = ((uint64_t)(in[j * 8 + 7] & 0xff)) |
                ((uint64_t)(in[j * 8 + 6] & 0xff) << 8) |
                ((uint64_t)(in[j * 8 + 5] & 0xff) << 16) |
                ((uint64_t)(in[j * 8 + 4] & 0xff) << 24) |
                ((uint64_t)(in[j * 8 + 3] & 0xff) << 32) |
                ((uint64_t)(in[j * 8 + 2] & 0xff) << 40) |
                ((uint64_t)(in[j * 8 + 1] & 0xff) << 48) |
                ((uint64_t)(in[j * 8 + 0] & 0xff) << 56);
    }
    for (int j = 16; j < 80; ++j) {
        W[j] = SSIG5121(W[j - 2]) + W[j - 7] + SSIG5120(W[j - 15]) + W[j - 16];
    }
}

std::string hashSHA224(std::string& in) {
    uint32_t H[8] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
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
            uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K256[t] + W[t];
            uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
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

    uint8_t hashValue[28];
    for (int i = 0; i < 7; i++) { // Only take the first 7 words (224 bits)
        hashValue[i * 4 + 0] = (H[i] >> 24) & 0xFF;
        hashValue[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hashValue[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hashValue[i * 4 + 3] = H[i] & 0xFF;
    }

    std::ostringstream oss;
    for (int i = 0; i < 28; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}

std::string hashSHA256(std::string& in) {
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
            uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K256[t] + W[t];
            uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
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
    for (int i = 0; i < 8; i++) { // Only take the first 8 words (256 bits)
        hashValue[i * 4 + 0] = (H[i] >> 24) & 0xFF;
        hashValue[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hashValue[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hashValue[i * 4 + 3] = H[i] & 0xFF;
    }

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}

std::string hashSHA384(std::string& in) {
    uint64_t H[8] = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };

    applySha512Padding(in);

    for (size_t i = 0; i < in.length(); i+=128) {
        uint64_t W[80];
        std::string chunk = in.substr(i, 128);
        fillBlock512(chunk, W);

        // Initialize hash value for this chunk
        uint64_t a = H[0];
        uint64_t b = H[1];
        uint64_t c = H[2];
        uint64_t d = H[3];
        uint64_t e = H[4];
        uint64_t f = H[5];
        uint64_t g = H[6];
        uint64_t h = H[7];

        for (size_t t = 0; t < 80; t++) {
            uint64_t T1 = h + BSIG5121(e) + CH(e, f, g) + K512[t] + W[t];
            uint64_t T2 = BSIG5120(a) + MAJ(a, b, c);
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

    uint8_t hashValue[48];
    for (int i = 0; i < 6; i++) { // Only take the first 6 words (384 bits)
        hashValue[i * 8 + 0] = (H[i] >> 56) & 0xFF;
        hashValue[i * 8 + 1] = (H[i] >> 48) & 0xFF;
        hashValue[i * 8 + 2] = (H[i] >> 40) & 0xFF;
        hashValue[i * 8 + 3] = (H[i] >> 32) & 0xFF;
        hashValue[i * 8 + 4] = (H[i] >> 24) & 0xFF;
        hashValue[i * 8 + 5] = (H[i] >> 16) & 0xFF;
        hashValue[i * 8 + 6] = (H[i] >> 8) & 0xFF;
        hashValue[i * 8 + 7] = H[i] & 0xFF;
    }

    std::ostringstream oss;
    for (int i = 0; i < 48; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}

std::string hashSHA512(std::string& in) {
    uint64_t H[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    applySha512Padding(in);

    for (size_t i = 0; i < in.length(); i+=128) {
        uint64_t W[80];
        std::string chunk = in.substr(i, 128);
        fillBlock512(chunk, W);

        // Initialize hash value for this chunk
        uint64_t a = H[0];
        uint64_t b = H[1];
        uint64_t c = H[2];
        uint64_t d = H[3];
        uint64_t e = H[4];
        uint64_t f = H[5];
        uint64_t g = H[6];
        uint64_t h = H[7];

        for (size_t t = 0; t < 80; t++) {
            uint64_t T1 = h + BSIG5121(e) + CH(e, f, g) + K512[t] + W[t];
            uint64_t T2 = BSIG5120(a) + MAJ(a, b, c);
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

    uint8_t hashValue[64];
    for (int i = 0; i < 8; i++) { // Only take the first 8 words (512 bits)
        hashValue[i * 8 + 0] = (H[i] >> 56) & 0xFF;
        hashValue[i * 8 + 1] = (H[i] >> 48) & 0xFF;
        hashValue[i * 8 + 2] = (H[i] >> 40) & 0xFF;
        hashValue[i * 8 + 3] = (H[i] >> 32) & 0xFF;
        hashValue[i * 8 + 4] = (H[i] >> 24) & 0xFF;
        hashValue[i * 8 + 5] = (H[i] >> 16) & 0xFF;
        hashValue[i * 8 + 6] = (H[i] >> 8) & 0xFF;
        hashValue[i * 8 + 7] = H[i] & 0xFF;
    }

    std::ostringstream oss;
    for (int i = 0; i < 64; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}

std::string hashSHA512_224(std::string& in) {
    uint64_t H[8] = {
        0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1
    };

    applySha512Padding(in);

    for (size_t i = 0; i < in.length(); i+=128) {
        uint64_t W[80];
        std::string chunk = in.substr(i, 128);
        fillBlock512(chunk, W);

        // Initialize hash value for this chunk
        uint64_t a = H[0];
        uint64_t b = H[1];
        uint64_t c = H[2];
        uint64_t d = H[3];
        uint64_t e = H[4];
        uint64_t f = H[5];
        uint64_t g = H[6];
        uint64_t h = H[7];

        for (size_t t = 0; t < 80; t++) {
            uint64_t T1 = h + BSIG5121(e) + CH(e, f, g) + K512[t] + W[t];
            uint64_t T2 = BSIG5120(a) + MAJ(a, b, c);
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

    uint8_t hashValue[28];
    for (int i = 0; i < 3; i++) { // Only take the first 7 words (224 bits)
        hashValue[i * 8 + 0] = (H[i] >> 56) & 0xFF;
        hashValue[i * 8 + 1] = (H[i] >> 48) & 0xFF;
        hashValue[i * 8 + 2] = (H[i] >> 40) & 0xFF;
        hashValue[i * 8 + 3] = (H[i] >> 32) & 0xFF;
        hashValue[i * 8 + 4] = (H[i] >> 24) & 0xFF;
        hashValue[i * 8 + 5] = (H[i] >> 16) & 0xFF;
        hashValue[i * 8 + 6] = (H[i] >> 8) & 0xFF;
        hashValue[i * 8 + 7] = H[i] & 0xFF;
    }
    // Take the upper 32 bits of the fourth word (32 bits)
    hashValue[24] = (H[3] >> 56) & 0xFF;
    hashValue[25] = (H[3] >> 48) & 0xFF;
    hashValue[26] = (H[3] >> 40) & 0xFF;
    hashValue[27] = (H[3] >> 32) & 0xFF;

    std::ostringstream oss;
    for (int i = 0; i < 28; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}

std::string hashSHA512_256(std::string& in) {
    uint64_t H[8] = {
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2
    };

    applySha512Padding(in);

    for (size_t i = 0; i < in.length(); i+=128) {
        uint64_t W[80];
        std::string chunk = in.substr(i, 128);
        fillBlock512(chunk, W);

        // Initialize hash value for this chunk
        uint64_t a = H[0];
        uint64_t b = H[1];
        uint64_t c = H[2];
        uint64_t d = H[3];
        uint64_t e = H[4];
        uint64_t f = H[5];
        uint64_t g = H[6];
        uint64_t h = H[7];

        for (size_t t = 0; t < 80; t++) {
            uint64_t T1 = h + BSIG5121(e) + CH(e, f, g) + K512[t] + W[t];
            uint64_t T2 = BSIG5120(a) + MAJ(a, b, c);
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
    for (int i = 0; i < 4; i++) { // Only take the first 4 words (256 bits)
        hashValue[i * 8 + 0] = (H[i] >> 56) & 0xFF;
        hashValue[i * 8 + 1] = (H[i] >> 48) & 0xFF;
        hashValue[i * 8 + 2] = (H[i] >> 40) & 0xFF;
        hashValue[i * 8 + 3] = (H[i] >> 32) & 0xFF;
        hashValue[i * 8 + 4] = (H[i] >> 24) & 0xFF;
        hashValue[i * 8 + 5] = (H[i] >> 16) & 0xFF;
        hashValue[i * 8 + 6] = (H[i] >> 8) & 0xFF;
        hashValue[i * 8 + 7] = H[i] & 0xFF;
    }

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    return oss.str();
}