/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pem.h
 */

#pragma once

#include <string>
#include <vector>

#include "rsa/rsa_key_generation/rsaKeyGen.h"

class PEMDecoder {
private:
    static std::vector<uint8_t> extractDER(const std::string& pem,
                                           const std::string& expectedHeader);

public:
    // RSA public keys
    static RSAPublicKey decodeRSAPublicKeyFromPKCS1(const std::string& pem);
    static RSAPublicKey decodeRSAPublicKeyFromPKCS8(const std::string& pem);

    // RSA private keys
    static RSAKeyPair decodeRSAPrivateKeyFromPKCS1(const std::string& pem);
    static RSAKeyPair decodeRSAPrivateKeyFromPKCS8(const std::string& pem);
};

class PEMEncoder {
private:
    static std::string wrapDER(const std::vector<uint8_t>& der,
                               const std::string& header);

public:
    // RSA public keys
    static std::string encodeRSAPublicKeyToPKCS1(const RSAPublicKey& key);
    static std::string encodeRSAPublicKeyToPKCS8(const RSAPublicKey& key);

    // RSA private keys
    static std::string encodeRSAPrivateKeyToPKCS1(const RSAKeyPair& key);
    static std::string encodeRSAPrivateKeyToPKCS8(const RSAKeyPair& key);
};
