/*
 * sha1Core.cpp
 *
 * Author: Hunter L, Richardson
 * Date: 2024-03-15
 */

#include "sha1Core.h"

#include <iostream>

bool shaConnectionTest() {
    return true;
}

SHA1::SHA1() {
    // Constructor implementation, if needed
}

void SHA1::applySha1Padding(std::string& in) {
    size_t messageLength = in.length() * 8;

    if (messageLength % 512 != 0) {
        // Pre-processing
        in += (char)0x80;
        while ((in.length() % 64) != 56) {
            in += (char)0x00;
        }

        // Append original message length in bits
        for (int i = 7; i >= 0; --i) {
            in += (char)((messageLength >> (i * 8)) & 0xFF);
        }
    }
}


void testSHA1Functions::testSHA1Padding(std::string& in) {
    this->SHA1Object.applySha1Padding(in);
}