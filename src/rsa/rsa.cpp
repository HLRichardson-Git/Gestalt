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

BigInt RSA::encrypt(const std::string& plaintext, ENCRYPTION_PADDING_SCHEME paddingScheme) {
    BigInt x = plaintext;
    BigInt result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    return result;
}

BigInt RSA::decrypt(const std::string& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme) {
    BigInt y = ciphertext;
    BigInt result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, y.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
    // TODO: implement CRT
    mpz_powm(result.n, y.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
    return result;
}

BigInt RSA::decrypt(const BigInt& ciphertext, ENCRYPTION_PADDING_SCHEME paddingScheme) {
    BigInt result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, y.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
    // TODO: implement CRT
    mpz_powm(result.n, ciphertext.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
    return result;
}