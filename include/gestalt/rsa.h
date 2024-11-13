/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa.h
 *
 * RSA is a widely used asymmetric encryption algorithm that relies on the difficulty of factoring 
 * large numbers. The class provides both basic RSA operations (without padding) and secure 
 * operations with padding schemes for enhanced security.
 * 
 * This file defines the RSA class, which provides functionality for RSA encryption, 
 * decryption, digital signatures, and signature verification. The RSA class supports 
 * both raw RSA operations and padded encryption/signature schemes (e.g., OAEP and PSS).
 * 
 */

# pragma once

#include "rsa/rsa_key_generation/rsaKeyGen.h"
#include "rsa/padding_schemes/rsa_padding.h"

class RSA { 
private:
    RSAKeyPair keyPair; 

    BigInt rawEncrypt(const BigInt& plaintext, const RSAPublicKey& recipientPublicKey) const;
    BigInt rawDecrypt(const BigInt& ciphertext) const;

    BigInt rawSignatureGen(const BigInt& messageHash) const;
    BigInt rawSignatureVer(const BigInt& signature, const RSAPublicKey& recipientPublicKey) const;

public:
    RSA() {};
    RSA(RSAKeyGenOptions keyGenerationOptions) // TODO: Make a unit test for this constructor
        : keyPair(keyGenerationOptions) {}
    RSA(RSASecurityStrength specifiedStength, const RSAPrivateKey& privateKey, const RSAPublicKey& publicKey) 
        : keyPair(specifiedStength, privateKey, publicKey) {}

    RSAPrivateKey getPrivateKey() const { return keyPair.getPrivateKey(); };
    RSAPublicKey getPublicKey() const { return keyPair.getPublicKey(); };

    std::string encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey);
    std::string encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey, const OAEPParams& parameters);

    std::string decrypt(const std::string& ciphertext);
    std::string decrypt(const std::string& ciphertext, const OAEPParams& parameters);

    std::string signMessage(const std::string& message, HashAlgorithm hashAlg = HashAlgorithm::None);
    std::string signMessage(const std::string& message, const PSSParams& parameters, HashAlgorithm hashAlg = HashAlgorithm::None);

    bool verifySignature(const std::string& message, const std::string& signature, const RSAPublicKey& recipientPublicKey, HashAlgorithm hashAlg = HashAlgorithm::None);
    bool verifySignature(const std::string& message, const std::string& signature, const RSAPublicKey& recipientPublicKey, const PSSParams& parameters, HashAlgorithm hashAlg = HashAlgorithm::None);
};