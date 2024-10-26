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
#include "rsa/rsaObjects.h"
#include "rsa/padding_schemes/oaep/oaep.h"
#include "rsa/padding_schemes/pss/pss.h"

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

    std::string signMessage(const std::string& messageHash, SIGNATURE_PADDING_SCHEME paddingScheme);
    std::string signMessage(const std::string& messageHash, const PSSParams& parameters);

    bool verifySignature(const std::string& messageHash, const std::string& signature, SIGNATURE_PADDING_SCHEME paddingScheme);
    bool verifySignature(const std::string& messageHash, const std::string& signature, const RSAPublicKey& recipientPublicKey, const PSSParams& parameters);
};