/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der.h
 */

#pragma once

#include "rsa/rsa_key_generation/rsaKeyGen.h"
#include "../object_identifiers.h"

#include <vector>
#include <string>

class DERDecoder {
private:
    const std::vector<uint8_t>& data;
    size_t pos;
    
    // Core DER reading methods
    size_t readSequence();
    void readBitString();
    void readNull();
    void readNullIfPresent();
    uint8_t readTag();
    size_t readLength();
    BigInt readIntegerAsBigInt();
    
    // OID handling methods
    std::string readObjectIdentifier();
    void expectRSAObjectIdentifier();  // Accepts any valid RSA OID
    bool isValidRSAOid(const std::string& oid);
    
    // Validation
    void validateRSAPublicKey(const BigInt& modulus, const BigInt& exponent);
    
public:
    DERDecoder(const std::vector<uint8_t>& data) 
        : data(data), pos(0) {}
    
    void printDerAtPosition(); // For debugging
    
    // Key decoding methods - explicit format
    RSAPublicKey decodeRSAPublicKeyFromPKCS8();
    RSAPublicKey decodeRSAPublicKeyFromPKCS1();
    
    // Auto-detect format
    RSAPublicKey decodeRSAPublicKeyFromDER();
    
    // Utility methods
    KeyFormat detectPublicKeyFormat();
};

class DEREncoder {
private:
    std::vector<uint8_t> buffer;
    
    // Core DER writing methods
    void writeTag(uint8_t tag);
    void writeLength(size_t length);
    void writeInteger(const BigInt& value);
    void writeSequence(const std::vector<uint8_t>& content);
    void writeObjectIdentifier(const std::string& oidHex);
    void writeNull();
    void writeBitString(const std::vector<uint8_t>& data);
    
    // Helper methods
    std::vector<uint8_t> encodeLength(size_t length);
    std::vector<uint8_t> encodeInteger(const BigInt& value);
    std::vector<uint8_t> encodeBigIntToBytes(const BigInt& value);
    std::vector<uint8_t> wrapInSequence(const std::vector<uint8_t>& content);
    const std::vector<uint8_t>& getBuffer() const { return buffer; }
    void clear() { buffer.clear(); }
    
    // Validation
    void validateRSAPublicKey(const RSAPublicKey& key);
    
public:
    DEREncoder() = default;
    
    // Key encoding methods - explicit format
    std::vector<uint8_t> encodeRSAPublicKeyToPKCS1(const RSAPublicKey& key);
    std::vector<uint8_t> encodeRSAPublicKeyToPKCS8(const RSAPublicKey& key);

    // Generic function that by defauly encodes in PKCS8 format
    std::vector<uint8_t> encodeRSAPublicKeyToDER(const RSAPublicKey& key, KeyFormat format = KeyFormat::PKCS8);
};