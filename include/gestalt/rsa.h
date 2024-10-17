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

class RSA { 
private:
    RSAKeyPair keyPair; 

public:
    RSA() {};
    RSA(RSA_SECURITY_STRENGTH specifiedStength, const RSAPrivateKey& privateKey, const RSAPublicKey& publicKey) 
        : keyPair(specifiedStength, privateKey, publicKey) {}

    RSAPrivateKey getPrivateKey() const { return keyPair.getPrivateKey(); };
    RSAPublicKey getPublicKey() const { return keyPair.getPublicKey(); };

    BigInt encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey);
    BigInt encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey, const OAEPParams& parameters);
    //BigInt encryptTest(const std::string& plaintext, const OAEPParams& parameters);
    BigInt decrypt(const std::string& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme);
    BigInt decrypt(const std::string& ciphertext, const OAEPParams& parameters);
    BigInt decrypt(const BigInt& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme);

    BigInt signMessage(const std::string& message, SIGNATURE_PADDING_SCHEME paddingScheme);
    bool signMessage(const std::string& message, const BigInt& signature, SIGNATURE_PADDING_SCHEME paddingScheme);
};