/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der.cpp
 * 
 */

#include "der.h"
#include "utils.h"

#include <iostream>
#include <iomanip>

uint8_t DERParser::readTag() {
    if (pos >= data.size()) {
        throw std::runtime_error("Unexpected end of DER data 3");
    }
    return data[pos++];
}

void DERParser::readSequence() {
    uint8_t tag = readTag();
    if (tag != 0x30) throw std::runtime_error("Expected SEQUENCE tag");

    size_t length = readLength();
}

void DERParser::readObject() {
    uint8_t tag = readTag();
    if (tag != 0x06) throw std::runtime_error("Expected OBJECT IDENTIFIER tag");

    size_t length = readLength();

    std::string objectIdentifier;
    for (size_t i = 0; i < length; i++) {
        objectIdentifier.push_back(data[pos++]);
    }

    if (bytesToHex(objectIdentifier) != "2a864886f70d010101") {
        throw std::runtime_error("Expected RSA Encryption OBJECT IDENTIFIER");
    }
}

void DERParser::readNull() {
    uint8_t tag = readTag();
    if (tag != 0x05) throw std::runtime_error("Expected NULL tag");

    size_t length = readLength();
    if (length != 0) throw std::runtime_error("Invalid NULL length");
}

void DERParser::readBitString() {
    uint8_t tag = readTag();
    if (tag != 0x03) throw std::runtime_error("Expected BIT STRING tag");

    size_t length = readLength();
    if (length == 0) throw std::runtime_error("Invalid BIT STRING length");

    uint8_t unusedBits = data[pos++]; // Read the number of unused bits
    // All RSA keys should be byte-aligned so unusedBits should be zero
    if (unusedBits != 0) throw std::runtime_error("Expected unused bits to be 0");
}

void DERParser::readInteger() {
    uint8_t tag = readTag();
    if (tag != 0x02) throw std::runtime_error("Expected INTEGER tag");
    size_t length = readLength();
    std::string integerValue;
    for (size_t i = 0; i < length; i++) {
        integerValue.push_back(data[pos++]);
    }
    std::cout << "Integer: " << bytesToHex(integerValue) << std::endl;
}

size_t DERParser::readLength() {
    if (pos >= data.size()) throw std::runtime_error("Unexpected end of DER data 1");
    uint8_t lenByte = data[pos++];
    if (lenByte & 0x80) { // Long form
        size_t lengthBytes = lenByte & 0x7F;
        if (lengthBytes > sizeof(size_t)) {
            throw std::runtime_error("Length too large");
        }
        size_t length = 0;
        for (size_t i = 0; i < lengthBytes; i++) {
            if (pos >= data.size()) throw std::runtime_error("Unexpected end of DER data 2");
            length = (length << 8) | data[pos++];
        }
        return length;
    } else { // Short form
        return lenByte;
    }
}

void DERParser::printDerAtPosition() {
    for (size_t i = pos; i < data.size(); ++i) {
        std::cout << std::setw(2) << std::setfill('0')
                  << std::hex << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
}

BigInt DERParser::readIntegerAsBigInt() {
    uint8_t tag = readTag();
    if (tag != 0x02) throw std::runtime_error("Expected INTEGER tag");

    size_t length = readLength();
    std::vector<uint8_t> integerBytes;
    for (size_t i = 0; i < length; i++) {
        integerBytes.push_back(data[pos++]);
    }

    // Convert the byte vector to a BigInt
    return BigInt(integerBytes);
}

//void DERParser::decodeDER() {
RSAPublicKey DERParser::decodeRSAKeyFromDER() {
    //std::cout << "Decoding DER..." << std::endl;
    readSequence(); // Outer sequence
    //printDerAtPosition();

    readSequence(); // Inner sequence
    //printDerAtPosition();

    readObject(); // Object identifier
    //printDerAtPosition();

    readNull(); // NULL tag
    //printDerAtPosition();

    readBitString(); // Bit string
    //printDerAtPosition();

    readSequence(); // Sequence for RSA parameters
    //printDerAtPosition();

    //readInteger(); // First integer (modulus)
    //printDerAtPosition();

    //readInteger(); // Second integer (exponent)
    //printDerAtPosition();

    // Parse the modulus (n)
    BigInt modulus = readIntegerAsBigInt(); // First integer (modulus)
    //printDerAtPosition();

    // Parse the exponent (e)
    BigInt exponent = readIntegerAsBigInt(); // Second integer (exponent)
    //printDerAtPosition();

    // Create and return the RSAPublicKey struct
    return RSAPublicKey(modulus, exponent);
}