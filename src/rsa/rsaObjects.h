/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaObjects.h
 *
 */

# pragma once

#include "bigInt/bigInt.h"

enum class RSA_SECURITY_STRENGTH {
   bits_1024,
   bits_2048,
   bits_3072,
   bits_7680,
   bits_15360 
};

enum class RANDOM_PRIME_METHOD {
    provable,
    probable,
    provableWithProvableAux,
    probableWithProvableAux,
    probableWithProbableAux
};

enum class ENCRYPTION_PADDING_SCHEME {
    NO_PADDING,
    PKCS1v15,
    OAEP
};

enum class SIGNATURE_PADDING_SCHEME {
    NO_PADDING,
    PKCS1v15,
    PSS
};

struct RSAKeyGenOptions {
    RSA_SECURITY_STRENGTH = RSA_SECURITY_STRENGTH::bits_2048;
    RANDOM_PRIME_METHOD = RANDOM_PRIME_METHOD::provable;
};

struct RSAPrivateKey {
    BigInt d;
};

struct RSAPublicKey {
    BigInt n;
    BigInt e = 65537;
};

class RSAKeyPair {
private:
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
    RSAKeyGenOptions keyGenOptions;

    void generateKeyPair(RSAKeyGenOptions options);

    friend class RSA;
public:

    RSAKeyPair() : keyGenOptions() { 
        generateKeyPair(keyGenOptions); 
    };
    RSAKeyPair(const BigInt& d, const BigInt& n) : privateKey{d}, publicKey{n}, keyGenOptions() {}
    RSAKeyPair(const BigInt& d, const BigInt& n, const BigInt& e) : privateKey{d}, publicKey{n, e}, keyGenOptions() {}
    RSAKeyPair(const std::string& dStr, const std::string& nStr)
        : privateKey{BigInt(dStr)}, publicKey{BigInt(nStr)}, keyGenOptions() {}
    RSAKeyPair(const std::string& dStr, const std::string& nStr, const std::string& eStr)
        : privateKey{BigInt(dStr)}, publicKey{BigInt(nStr), BigInt(eStr)}, keyGenOptions() {}

    void setPrivateKey(BigInt other) { privateKey.d = other; };
    void setPublicKey(BigInt otherModulus, BigInt otherExponent) { 
        publicKey.n = otherModulus;
        publicKey.e = otherExponent;
    };
}