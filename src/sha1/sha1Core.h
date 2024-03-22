/*
 * sha1Core.h
 *
 * This file contains the declaration of the SHA-1 (Secure Hash Algorithm 1) hashing function in C++.
 * SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value, typically represented as a
 * 40-digit hexadecimal number. It is widely used in security applications and protocols, including TLS, SSL, SSH, and
 * IPsec.
 *
 * The implementation follows the SHA-1 specification, as defined by the National Institute of Standards and Technology
 * (NIST) and RFC 3174.
 *
 * This header provides the declaration of the SHA1 class, which encapsulates the functionality to generate SHA-1
 * hashes from input strings.
 *
 * Author: Hunter L, Richardson
 * Date: 2024-03-17
 */

#pragma once

#include <string>

class SHA1 {
private:
    // size of entire block to be compressed
    static const unsigned int BLOCK_SIZE = 80;

    // Nothing under the sleves constatns from ref [1]
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xc3d2e1f0;

    std::string digest();
    void reset();
    void fillBlock(std::string in, uint32_t w[BLOCK_SIZE]);
    void applySha1Padding(std::string& in);

public:

	SHA1();
	~SHA1() {}

    std::string hash(std::string in);

    friend class testSHA1Functions;
};

// Friend class to test components of SHA1 class
class testSHA1Functions {
private:

    static const unsigned int BLOCK_SIZE = 80;
    SHA1 SHA1Object;
public:

    void testSHA1FillBlock(std::string in, uint32_t computedW[BLOCK_SIZE]);
    void testSHA1Padding(std::string& in);
};