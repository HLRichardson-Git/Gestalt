/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der_decoder.cpp
 * 
 */

#include "der.h"
#include "utils.h"
#include "../object_identifiers.h"

#include <iostream>
#include <iomanip>
#include <sstream>

uint8_t DERDecoder::readTag() {
    if (pos >= data.size()) {
        throw std::runtime_error("Unexpected end of DER data at position " + std::to_string(pos));
    }
    return data[pos++];
}

size_t DERDecoder::readSequence() {
    uint8_t tag = readTag();
    if (tag != 0x30) {
        std::stringstream ss;
        ss << "Expected SEQUENCE tag (0x30) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }
    
    size_t length = readLength();
    size_t sequenceEnd = pos + length;
    
    // Validate sequence doesn't extend past data
    if (sequenceEnd > data.size()) {
        throw std::runtime_error("SEQUENCE length (" + std::to_string(length) + 
                                 ") exceeds available data at position " + 
                                 std::to_string(pos));
    }
    
    return sequenceEnd;
}

std::string DERDecoder::readObjectIdentifier() {
    uint8_t tag = readTag();
    if (tag != 0x06) {
        std::stringstream ss;
        ss << "Expected OBJECT IDENTIFIER tag (0x06) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    
    // Validate we have enough data
    if (pos + length > data.size()) {
        throw std::runtime_error("OID length exceeds available data");
    }
    
    std::string objectIdentifier;
    for (size_t i = 0; i < length; i++) {
        objectIdentifier.push_back(data[pos++]);
    }

    return bytesToHex(objectIdentifier);
}

bool DERDecoder::isValidRSAOid(const std::string& oid) {
    return oid == OID_RSA_ENCRYPTION || 
           oid == OID_RSA_SSA_PSS || 
           oid == OID_RSA_OAEP;
}

void DERDecoder::expectRSAObjectIdentifier() {
    std::string actualOid = readObjectIdentifier();
    
    if (!isValidRSAOid(actualOid)) {
        throw std::runtime_error(
            "Expected RSA OID (rsaEncryption, RSASSA-PSS, or RSA-OAEP), got: " + actualOid
        );
    }
}

void DERDecoder::readNullIfPresent() {
    // Check if next byte is NULL tag
    if (pos >= data.size()) {
        return; // No more data, NULL is optional
    }
    
    if (data[pos] == 0x05) {
        readNull();
    }
    // If not NULL, it's optional and we continue
}

void DERDecoder::readNull() {
    uint8_t tag = readTag();
    if (tag != 0x05) {
        std::stringstream ss;
        ss << "Expected NULL tag (0x05) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    if (length != 0) {
        throw std::runtime_error("Invalid NULL length: " + std::to_string(length) + 
                                 " (expected 0)");
    }
}

void DERDecoder::readBitString() {
    uint8_t tag = readTag();
    if (tag != 0x03) {
        std::stringstream ss;
        ss << "Expected BIT STRING tag (0x03) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    if (length == 0) {
        throw std::runtime_error("Invalid BIT STRING length: 0");
    }
    
    // Validate we have enough data
    if (pos + length > data.size()) {
        throw std::runtime_error("BIT STRING length exceeds available data");
    }

    uint8_t unusedBits = data[pos++];
    
    // Most RSA keys have 0 unused bits, but up to 7 is technically valid
    if (unusedBits > 7) {
        throw std::runtime_error("Invalid unused bits in BIT STRING: " + 
                                 std::to_string(unusedBits) + " (max 7)");
    }
    
    // For RSA public keys, we typically expect 0 unused bits
    if (unusedBits != 0) {
        std::cerr << "Warning: BIT STRING has " << (int)unusedBits 
                  << " unused bits (unusual for RSA keys)" << std::endl;
    }
}

size_t DERDecoder::readLength() {
    if (pos >= data.size()) {
        throw std::runtime_error("Unexpected end of DER data while reading length");
    }
    
    uint8_t lenByte = data[pos++];
    
    if (lenByte & 0x80) { // Long form
        size_t lengthBytes = lenByte & 0x7F;
        
        // Validate length encoding
        if (lengthBytes == 0) {
            throw std::runtime_error("Invalid indefinite length encoding");
        }
        
        if (lengthBytes > sizeof(size_t)) {
            throw std::runtime_error("Length field too large: " + 
                                     std::to_string(lengthBytes) + " bytes");
        }
        
        // Check we have enough bytes for the length
        if (pos + lengthBytes > data.size()) {
            throw std::runtime_error("Insufficient data for length field");
        }
        
        size_t length = 0;
        for (size_t i = 0; i < lengthBytes; i++) {
            length = (length << 8) | data[pos++];
        }
        
        // Validate DER requires minimal encoding (no leading zeros in long form)
        if (lengthBytes > 1 && length < 128) {
            throw std::runtime_error("Non-minimal length encoding");
        }
        
        return length;
    } else { // Short form
        return lenByte;
    }
}

void DERDecoder::printDerAtPosition() {
    for (size_t i = pos; i < data.size(); ++i) {
        std::cout << std::setw(2) << std::setfill('0')
                  << std::hex << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
}

BigInt DERDecoder::readIntegerAsBigInt() {
    uint8_t tag = readTag();
    if (tag != 0x02) {
        std::stringstream ss;
        ss << "Expected INTEGER tag (0x02) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    if (length == 0) {
        throw std::runtime_error("INTEGER length cannot be zero");
    }
    
    // Validate we have enough data
    if (pos + length > data.size()) {
        throw std::runtime_error("INTEGER length exceeds available data");
    }
    
    // Check for negative integers (shouldn't happen in public keys)
    if (data[pos] & 0x80 && !(data[pos] == 0x00 && length > 1)) {
        throw std::runtime_error("Negative INTEGER detected (invalid for RSA public key)");
    }
    
    std::vector<uint8_t> integerBytes;
    
    // DER encoding adds a leading 0x00 for positive integers with high bit set
    bool hasPadding = (data[pos] == 0x00 && length > 1);
    
    if (hasPadding) {
        // Check for multiple padding bytes (DER violation)
        if (length > 2 && data[pos + 1] == 0x00) {
            throw std::runtime_error("Multiple leading zero bytes in INTEGER (non-minimal encoding)");
        }
        
        // Check that padding was necessary (next byte should have high bit set)
        if (!(data[pos + 1] & 0x80)) {
            throw std::runtime_error("Unnecessary leading zero byte in INTEGER");
        }
        
        pos++; // Skip the padding byte
        
        // Read remaining bytes
        for (size_t i = 0; i < length - 1; i++) {
            integerBytes.push_back(data[pos++]);
        }
    } else {
        // Read all bytes
        for (size_t i = 0; i < length; i++) {
            integerBytes.push_back(data[pos++]);
        }
    }
    
    // Validate integer isn't unreasonably large (e.g., > 16384 bits)
    if (integerBytes.size() > 2048) {
        throw std::runtime_error("INTEGER is unreasonably large: " + 
                                 std::to_string(integerBytes.size() * 8) + " bits");
    }

    return BigInt(integerBytes);
}

void DERDecoder::validateRSAPublicKey(const BigInt& modulus, const BigInt& exponent) {
    // Get bit lengths
    size_t modulusBits = modulus.bitLength();
    size_t exponentBits = exponent.bitLength();
    
    // Modulus should be at least 512 bits (though 2048+ is recommended)
    if (modulusBits < 512) {
        throw std::runtime_error("RSA modulus too small: " + std::to_string(modulusBits) + 
                                 " bits (minimum 512)");
    }
    
    // Warn about weak keys
    if (modulusBits < 2048) {
        std::cerr << "Warning: RSA modulus is only " << modulusBits 
                  << " bits (2048+ recommended)" << std::endl;
    }
    
    // Modulus should be odd (required for RSA)
    if (modulus.isEven()) {
        throw std::runtime_error("RSA modulus must be odd");
    }
    
    // Exponent should be at least 3
    if (exponent < 3) {
        throw std::runtime_error("RSA exponent too small: must be at least 3");
    }
    
    // Exponent must be odd (required for RSA)
    if (exponent.isEven()) {
        throw std::runtime_error("RSA exponent must be odd");
    }
    
    // Exponent should be less than modulus
    if (exponent >= modulus) {
        throw std::runtime_error("RSA exponent must be less than modulus");
    }
    
    // Common exponents are 3, 17, or 65537
    // Warn if using an unusual exponent
    if (exponent != 3 && exponent != 17 && exponent != 65537) {
        std::cerr << "Warning: Unusual RSA exponent detected" << std::endl;
    }
}

RSAPublicKey DERDecoder::decodeRSAPublicKeyFromPKCS8() {
    // PKCS#8 SubjectPublicKeyInfo structure
    size_t outerEnd = readSequence(); // Outer sequence
    size_t algIdEnd = readSequence(); // AlgorithmIdentifier sequence
    
    expectRSAObjectIdentifier();
    
    // NULL is optional in some encodings
    readNullIfPresent();
    
    // Validate we're still within AlgorithmIdentifier
    if (pos > algIdEnd) {
        throw std::runtime_error("Read past end of AlgorithmIdentifier");
    }
    
    readBitString(); // Bit string containing the PKCS#1 key
    readSequence(); // Inner PKCS#1 RSAPublicKey sequence

    // Parse the modulus (n) and exponent (e)
    BigInt modulus = readIntegerAsBigInt();
    BigInt exponent = readIntegerAsBigInt();
    
    // Validate the key parameters
    validateRSAPublicKey(modulus, exponent);
    
    // Validate we're at or near the end
    if (pos > outerEnd) {
        throw std::runtime_error("Read past end of outer SEQUENCE");
    }

    return RSAPublicKey(modulus, exponent);
}

RSAPublicKey DERDecoder::decodeRSAPublicKeyFromPKCS1() {
    // PKCS#1 RSAPublicKey structure
    size_t sequenceEnd = readSequence(); // Main sequence

    // Parse the modulus (n) and exponent (e) directly
    BigInt modulus = readIntegerAsBigInt();
    BigInt exponent = readIntegerAsBigInt();
    
    // Validate the key parameters
    validateRSAPublicKey(modulus, exponent);
    
    // Validate we're at the end of the sequence
    if (pos != sequenceEnd) {
        std::cerr << "Warning: Extra data at end of PKCS#1 key" << std::endl;
    }

    return RSAPublicKey(modulus, exponent);
}

RSAPublicKey DERDecoder::decodeRSAPublicKeyFromDER() {
    // Auto-detect format and parse accordingly
    size_t savedPos = pos;
    
    try {
        // Try PKCS#8 first (more common for public keys)
        return decodeRSAPublicKeyFromPKCS8();
    } catch (const std::runtime_error& e) {
        // Reset position and try PKCS#1
        pos = savedPos;
        try {
            return decodeRSAPublicKeyFromPKCS1();
        } catch (const std::runtime_error& e2) {
            throw std::runtime_error(
                "Failed to parse RSA public key. Not valid PKCS#8 or PKCS#1 format.\n"
                "PKCS#8 error: " + std::string(e.what()) + "\n" +
                "PKCS#1 error: " + std::string(e2.what())
            );
        }
    }
}

KeyFormat DERDecoder::detectPublicKeyFormat() {
    size_t savedPos = pos;
    
    try {
        readSequence(); // First sequence
        
        // Peek at the next tag
        if (pos >= data.size()) {
            throw std::runtime_error("Unexpected end of data after initial SEQUENCE");
        }
        
        uint8_t nextTag = data[pos];
        
        // Restore position
        pos = savedPos;
        
        if (nextTag == 0x30) {
            // Next element is a SEQUENCE, likely PKCS#8 (AlgorithmIdentifier)
            return KeyFormat::PKCS8;
        } else if (nextTag == 0x02) {
            // Next element is an INTEGER, likely PKCS#1
            return KeyFormat::PKCS1;
        } else {
            std::stringstream ss;
            ss << "Unknown key format: unexpected tag 0x" << std::hex << (int)nextTag;
            throw std::runtime_error(ss.str());
        }
    } catch (...) {
        pos = savedPos;
        throw;
    }
}