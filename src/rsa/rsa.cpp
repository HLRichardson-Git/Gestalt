/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa.cpp
 *
 */

#include <gestalt/rsa.h>
#include "padding_schemes/oaep/oaep.h"

BigInt RSA::encrypt(const std::string& plaintext, ENCRYPTION_PADDING_SCHEME paddingScheme) {
    //BigInt x = plaintext;
    std::string label = "";
    BigInt x;
    BigInt result;

    switch (paddingScheme) {
        case ENCRYPTION_PADDING_SCHEME::NO_PADDING:
            x = plaintext;
            break;
        case ENCRYPTION_PADDING_SCHEME::OAEP:
            x = applyOAEP_Padding(plaintext, label, keyPair.getModulusBitLength() / 8);
            break;
        case ENCRYPTION_PADDING_SCHEME::PKCS1v15:
            x = plaintext; // TODO
            break;
        default:
            throw std::invalid_argument("Unsupported padding scheme");
    }
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    return result;
}

BigInt RSA::decrypt(const std::string& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme) {
    BigInt y = ciphertext;
    BigInt m1, m2, h, result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
    //mpz_powm_sec(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
    mpz_powm(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
    mpz_powm(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
    h = (keyPair.privateKey.qInv * (m1 - m2)) % keyPair.privateKey.p;
    result = m2 + (h * keyPair.privateKey.q);
    
    return result;
}

BigInt RSA::decrypt(const BigInt& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme) {
    BigInt m1, m2, h, result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(m1.n, ciphertext.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
    //mpz_powm_sec(m2.n, ciphertext.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
    mpz_powm(m1.n, ciphertext.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
    mpz_powm(m2.n, ciphertext.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
    h = (keyPair.privateKey.qInv * (m1 - m2)) % keyPair.privateKey.p;
    result = m2 + (h * keyPair.privateKey.q);
    return result;
}