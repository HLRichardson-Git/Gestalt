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

BigInt RSA::rawEncrypt(const BigInt& plaintext, const RSAPublicKey& recipientPublicKey) const {
    BigInt result;
    // TODO: Use atleast v5 GMP for this secure function
    //mpz_powm_sec(result.n, x.n, keyPair.publicKey.e.n, keyPair.publicKey.n.n);
    mpz_powm(result.n, plaintext.n, recipientPublicKey.e.n, recipientPublicKey.n.n);
    return result;
}

BigInt RSA::rawDecrypt(const BigInt& ciphertext) const {
    BigInt result;

    // Check if CRT values are available (e.g., dP, dQ, p, q)
    if (mpz_sgn(keyPair.privateKey.dP.n) != 0 && mpz_sgn(keyPair.privateKey.dQ.n) != 0 &&
        mpz_sgn(keyPair.privateKey.p.n) != 0 && mpz_sgn(keyPair.privateKey.q.n) != 0) {

        // CRT-based decryption
        BigInt m1, m2, h;
        // TODO: Use atleast v5 GMP for this secure function
        //mpz_powm_sec(m1.n, y.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
        //mpz_powm_sec(m2.n, y.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
        mpz_powm(m1.n, ciphertext.n, keyPair.privateKey.dP.n, keyPair.privateKey.p.n);
        mpz_powm(m2.n, ciphertext.n, keyPair.privateKey.dQ.n, keyPair.privateKey.q.n);
        h = (keyPair.privateKey.qInv * (m1 - m2)) % keyPair.privateKey.p;
        result = m2 + (h * keyPair.privateKey.q);
    } else {
        // Standard RSA decryption without CRT
        // TODO: Use atleast v5 GMP for this secure function
        //mpz_powm_sec(result.n, y.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
        mpz_powm(result.n, ciphertext.n, keyPair.privateKey.d.n, keyPair.publicKey.n.n);
    }

    return result;
}

BigInt RSA::rawSignatureGen(const BigInt& messageHash) const {
    // Signature generation is the same as raw decryption using the private key.
    return rawDecrypt(messageHash);
}

BigInt RSA::rawSignatureVer(const BigInt& signature, const RSAPublicKey& recipientPublicKey) const {
    // Signature verification is the same as raw encryption using the public key.
    return rawEncrypt(signature, recipientPublicKey);
}

std::string RSA::encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey) {
    BigInt x = plaintext;
    return rawEncrypt(x, recipientPublicKey).toHexString();
}

std::string RSA::encrypt(const std::string& plaintext, const RSAPublicKey& recipientPublicKey, const OAEPParams& parameters) {
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    BigInt x = "0x" + convertToHex(applyOAEP_Padding(plaintext, parameters, modulusSizeInBytes));
    return rawEncrypt(x, recipientPublicKey).toHexString();
}

std::string RSA::decrypt(const std::string& ciphertext) {
    BigInt y = ciphertext;
    return rawDecrypt(y).toHexString();
}

std::string RSA::decrypt(const std::string& ciphertext, const OAEPParams& parameters) {
    BigInt y = ciphertext;
    BigInt result = rawDecrypt(y);

    /* 
     * GMP which is the library providing multiple precision numbers and maths operations strips leading zeros
     * so the following segement of code corrects this if needed.
     */
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    std::string hexString = result.toHexString();
    size_t hexStringLength = hexString.length();
    size_t expectedHexLength = modulusSizeInBytes * 2; // 2 hex digits per byte
    
    // Pad with leading zeros
    if (hexStringLength < expectedHexLength) {
        hexString = std::string(expectedHexLength - hexStringLength, '0') + hexString;
    }

    return convertToHex(removeOAEP_Padding(hexToBytes(hexString), parameters, modulusSizeInBytes));
}

std::string RSA::signMessage(const std::string& message, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);
    BigInt x = "0x" + messageHash;
    return rawSignatureGen(x).toHexString();
}

std::string RSA::signMessage(const std::string& message, const PSSParams& parameters, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    BigInt x = "0x" + convertToHex(encodePSS_Padding(messageHash, parameters, modulusSizeInBytes));
    return rawSignatureGen(x).toHexString();
}

bool RSA::verifySignature(const std::string& message, const std::string& signature, const RSAPublicKey& recipientPublicKey, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);
    
    BigInt sigInt = BigInt("0x" + signature);
    BigInt decryptedHash = rawSignatureVer(sigInt, recipientPublicKey);

    return decryptedHash == BigInt("0x" + messageHash);;
}

bool RSA::verifySignature(const std::string& message, const std::string& signature, const RSAPublicKey& recipientPublicKey, const PSSParams& parameters, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);

    BigInt sigInt = BigInt("0x" + signature);
    BigInt decryptedHash = rawSignatureVer(sigInt, recipientPublicKey);

    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    std::string hexString = decryptedHash.toHexString();
    size_t hexStringLength = hexString.length();
    size_t expectedHexLength = modulusSizeInBytes * 2; // 2 hex digits per byte
    
    // Pad with leading zeros
    if (hexStringLength < expectedHexLength) {
        hexString = std::string(expectedHexLength - hexStringLength, '0') + hexString;
    }

    std::string decryptedHashBytes = hexToBytes(hexString);

    bool result = verifyPSS_Padding(decryptedHashBytes, messageHash, parameters, modulusSizeInBytes);

    return result;
}