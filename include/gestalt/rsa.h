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

#include "rsa/rsaObjects.h"

class RSA { 
private:
    RSAKeyPair keyPair; 

public:
    RSA() {};
    RSA(const RSAPrivateKey& privateKey, const RSAPublicKey& publicKey) 
        : keyPair(privateKey, publicKey) {}

    RSAPrivateKey getPrivateKey() const { return keyPair.getPrivateKey(); };
    RSAPublicKey getPublicKey() const { return keyPair.getPublicKey(); };

    BigInt encrypt(const std::string& plaintext, ENCRYPTION_PADDING_SCHEME paddingScheme);
    BigInt decrypt(const std::string& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme);
    BigInt decrypt(const BigInt& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme);

    BigInt signMessage(const std::string& message, SIGNATURE_PADDING_SCHEME paddingScheme);
    bool signMessage(const std::string& message, const BigInt& signature, SIGNATURE_PADDING_SCHEME paddingScheme);
};