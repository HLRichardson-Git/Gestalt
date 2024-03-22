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
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-03-17
 */

#include "sha1Core.h"
#include "../tools/utils.h"

#include <iomanip>
#include <sstream>


SHA1::SHA1() {
    // Constructor implementation, if needed
}

/*
 * Generates the SHA-1 hash value for the input string.
 *
 * @param in The input string to be hashed.
 * @return The SHA-1 hash value as a hexadecimal string.
 */
std::string SHA1::hash(std::string in) {
    reset();
    applySha1Padding(in);

    for (size_t i = 0; i < in.length(); i += 64) {
        uint32_t w[BLOCK_SIZE];
        
        // Break the input into chunks of 64 bytes
        std::string chunk = in.substr(i, 64);
        // Fill SHA-1 block
        fillBlock(chunk, w);
        
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
 * @return The SHA-1 hash digest as a hexadecimal string.
 */
std::string SHA1::digest() {
    uint8_t hash[20];
    hash[0] = (h0 >> 24) & 0xFF;
    hash[1] = (h0 >> 16) & 0xFF;
    hash[2] = (h0 >> 8) & 0xFF;
    hash[3] = h0 & 0xFF;
    hash[4] = (h1 >> 24) & 0xFF;
    hash[5] = (h1 >> 16) & 0xFF;
    hash[6] = (h1 >> 8) & 0xFF;
    hash[7] = h1 & 0xFF;
    hash[8] = (h2 >> 24) & 0xFF;
    hash[9] = (h2 >> 16) & 0xFF;
    hash[10] = (h2 >> 8) & 0xFF;
    hash[11] = h2 & 0xFF;
    hash[12] = (h3 >> 24) & 0xFF;
    hash[13] = (h3 >> 16) & 0xFF;
    hash[14] = (h3 >> 8) & 0xFF;
    hash[15] = h3 & 0xFF;
    hash[16] = (h4 >> 24) & 0xFF;
    hash[17] = (h4 >> 16) & 0xFF;
    hash[18] = (h4 >> 8) & 0xFF;
    hash[19] = h4 & 0xFF;

    std::ostringstream oss;
    for (int i = 0; i < 20; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
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
 * @param in The input string from which data is filled into the block.
 * @param w The output block array.
 * @param index The starting index in the input string from which data is read.
 */
void SHA1::fillBlock(std::string in, uint32_t w[BLOCK_SIZE]) {
    for (int j = 0; j < 16; ++j) {
        w[j] = ((in[j * 4 + 3] & 0xff)) |
               ((in[j * 4 + 2] & 0xff) << 8) |
               ((in[j * 4 + 1] & 0xff) << 16) |
               ((in[j * 4 + 0] & 0xff) << 24);
    }
    for (int j = 16; j < 80; ++j) {
        uint32_t temp = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
        w[j] = (temp << 1) | (temp >> 31);
    }
}

/*
 * Applies SHA-1 padding to the input string.
 *
 * @param in The input string to which padding is applied.
 */
void SHA1::applySha1Padding(std::string& in) {
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

void testSHA1Functions::testSHA1FillBlock(std::string in, uint32_t computedW[BLOCK_SIZE]) {
    SHA1Object.applySha1Padding(in);
    this->SHA1Object.fillBlock(in, computedW);
}

void testSHA1Functions::testSHA1Padding(std::string& in) {
    this->SHA1Object.applySha1Padding(in);
}