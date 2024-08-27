/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa.cpp
 *
 */

#include <iostream> // for debugging

#include <gestalt/rsa.h>
#include "utils.h"

BigInt RSA::encrypt(const std::string& plaintext) {
    BigInt x = plaintext;
    BigInt result;

    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    return result;
}

BigInt RSA::encrypt(const std::string& plaintext, const OAEPParams& parameters) {
    BigInt x = "0x" + convertToHex(applyOAEP_Padding(plaintext, parameters, keyPair.getModulusBitLength() / 8));
    std::cout << "EM: " << x.toHexString() << std::endl;
    BigInt result;

    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    return result;
}

/*BigInt RSA::encryptTest(const std::string& plaintext, ENCRYPTION_PADDING_SCHEME paddingScheme, const std::string& label, const std::string& seed) {
    //BigInt x;
    std::string temp = "0x" + convertToHex(applyOAEP_Padding(plaintext, label, keyPair.getModulusBitLength() / 8, seed));
    BigInt x = temp;
    BigInt result;
    //std::string temp = "";

    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);

    std::cout << "x: " << x.toHexString() << std::endl;
    mpz_powm(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    return result;
}*/

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