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

std::string RSA::encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey) {
    BigInt x = plaintext;
    BigInt result;

    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, x.n, recipientPublicKey.e.n, recipientPublicKey.n.n);
    return result.toHexString();
}

std::string RSA::encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey, const OAEPParams& parameters) {
    BigInt x = "0x" + convertToHex(applyOAEP_Padding(plaintext, parameters, recipientPublicKey.getPublicModulusBitLength() / 8));
    BigInt result;

    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, x.n, recipientPublicKey.e.n, recipientPublicKey.n.n);
    return result.toHexString();
}

std::string RSA::decrypt(const std::string& ciphertext) {
    BigInt y = ciphertext;
    BigInt m1, m2, h, result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
    //mpz_powm_sec(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
    mpz_powm(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
    mpz_powm(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
    h = (keyPair.privateKey.qInv * (m1 - m2)) % keyPair.privateKey.p;
    result = m2 + (h * keyPair.privateKey.q);
    
    return result.toHexString();
}

std::string RSA::decrypt(const std::string& ciphertext, const OAEPParams& parameters) {
    BigInt y = ciphertext;
    BigInt result;

    // Check if CRT values are available (e.g., dP, dQ, p, q)
    if (mpz_sgn(keyPair.privateKey.dP.n) != 0 && mpz_sgn(keyPair.privateKey.dQ.n) != 0 &&
        mpz_sgn(keyPair.privateKey.p.n) != 0 && mpz_sgn(keyPair.privateKey.q.n) != 0) {

        // CRT-based decryption
        BigInt m1, m2, h;
        // TODO: Use atleast v5 GMP for this secure function
        //mpz_powm_sec(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
        //mpz_powm_sec(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
        mpz_powm(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
        mpz_powm(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
        h = (keyPair.privateKey.qInv * (m1 - m2)) % keyPair.privateKey.p;
        result = m2 + (h * keyPair.privateKey.q);
    } else {
        // Standard RSA decryption without CRT
        // TODO: Use atleast v5 GMP for this secure function
        //mpz_powm_sec(result.n, y.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
        mpz_powm(result.n, y.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
    }

    // Get the modulus size in bytes (key size)
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    
    // Convert result to hex and ensure it is padded to the correct length
    std::string hexString = result.toHexString();
    size_t hexStringLength = hexString.length();
    size_t expectedHexLength = modulusSizeInBytes * 2; // 2 hex digits per byte
    
    if (hexStringLength < expectedHexLength) {
        // Pad with leading zeros
        hexString = std::string(expectedHexLength - hexStringLength, '0') + hexString;
    }

    return convertToHex(removeOAEP_Padding(hexToBytes(hexString), parameters, modulusSizeInBytes));;
}