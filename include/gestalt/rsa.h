/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa.h
 *
 */

# pragma once

#include "rsa/rsa_key_generation/rsaKeyGen.h"
#include "rsa/padding_schemes/oaep/oaep.h"
#include "rsa/padding_schemes/pss/pss.h"
#include "rsa/padding_schemes/pkcs1v15/pkcs1v15.h"
#include "hash_utils/hash_utils.h"

class RSA { 
private:
    RSAKeyPair keyPair; 

    BigInt rawEncrypt(const BigInt& plaintext, const RSAPublicKey& recipientPublicKey) const;
    BigInt rawDecrypt(const BigInt& ciphertext) const;

    BigInt rawSignatureGen(const BigInt& messageHash) const;
    BigInt rawSignatureVer(const BigInt& signature, const RSAPublicKey& recipientPublicKey) const;

public:
    RSA() {};
    RSA(RSA_SECURITY_STRENGTH specifiedStength, const RSAPrivateKey& privateKey, const RSAPublicKey& publicKey) 
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