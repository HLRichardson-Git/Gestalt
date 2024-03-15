/*
 * sha1Core.h
 *
 * Author: Hunter L, Richardson
 * Date: 2024-03-15
 */

#pragma once

#include <string>
#include <cstdint>

bool shaConnectionTest();

class SHA1 {
private:
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    void applySha1Padding(std::string& in);

public:

	SHA1();
	~SHA1() {}

    //void applySha1Padding(std::string& in);
    friend class testSHA1Functions;

};

class testSHA1Functions {
private:

    SHA1 SHA1Object;
public:

    void testSHA1Padding(std::string& in);
};