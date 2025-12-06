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

