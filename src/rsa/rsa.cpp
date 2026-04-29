/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa.cpp
 *
 * RSA is a widely used asymmetric encryption algorithm that relies on the difficulty of factoring
 * large numbers. The class provides both basic RSA operations (without padding) and secure
 * operations with padding schemes for enhanced security.
 *
 * This file defines the RSA class, which provides functionality for RSA encryption,
 * decryption, digital signatures, and signature verification. The RSA class supports
 * both raw RSA operations and padded encryption/signature schemes (e.g., OAEP and PSS).
 *
 */

#include <gestalt/rsa.h>
#include "rsa/padding_schemes/oaep/oaep.h"
#include "rsa/padding_schemes/pss/pss.h"
#include "rsa/padding_schemes/pkcs1v15/pkcs1v15.h"
#include "hash_utils/hash_utils.h"

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

static std::string padToEvenHex(std::string hex) {
    if (hex.size() % 2 != 0) hex = "0" + hex;
    return hex;
}

SecureBytes RSA::encrypt(const SecureBytes& plaintext, const RSAPublicKey& recipientPublicKey) {
    BigInt x = "0x" + plaintext.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawEncrypt(x, recipientPublicKey).toHexString()));
}

SecureBytes RSA::encrypt(const SecureBytes& plaintext, const RSAPublicKey& recipientPublicKey, const OAEPParams& parameters) {
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = applyOAEP_Padding(plaintext, parameters, modulusSizeInBytes);
    BigInt x = "0x" + padded.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawEncrypt(x, recipientPublicKey).toHexString()));
}

SecureBytes RSA::decrypt(const SecureBytes& ciphertext) {
    BigInt y = "0x" + ciphertext.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawDecrypt(y).toHexString()));
}

SecureBytes RSA::decrypt(const SecureBytes& ciphertext, const OAEPParams& parameters) {
    BigInt y = "0x" + ciphertext.toHex();
    BigInt result = rawDecrypt(y);

    /*
     * GMP which is the library providing multiple precision numbers and maths operations strips leading zeros
     * so the following segement of code corrects this if needed.
     */
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    std::string hexString = result.toHexString();
    size_t expectedHexLength = modulusSizeInBytes * 2; // 2 hex digits per byte

    // Pad with leading zeros
    if (hexString.length() < expectedHexLength) {
        hexString = std::string(expectedHexLength - hexString.length(), '0') + hexString;
    }

    return removeOAEP_Padding(SecureBytes::fromHex(hexString), parameters, modulusSizeInBytes);
}

SecureBytes RSA::signMessage(const SecureBytes& message, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt x = "0x" + messageHash.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawSignatureGen(x).toHexString()));
}

SecureBytes RSA::signMessage(const SecureBytes& message, const PSSParams& parameters, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = encodePSS_Padding(messageHash, parameters, modulusSizeInBytes);
    BigInt x = "0x" + padded.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawSignatureGen(x).toHexString()));
}

bool RSA::verifySignature(const SecureBytes& message, const SecureBytes& signature, const RSAPublicKey& recipientPublicKey, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);

    BigInt sigInt = BigInt("0x" + signature.toHex());
    BigInt decryptedHash = rawSignatureVer(sigInt, recipientPublicKey);

    return decryptedHash == BigInt("0x" + messageHash.toHex());
}

bool RSA::verifySignature(const SecureBytes& message, const SecureBytes& signature, const RSAPublicKey& recipientPublicKey, const PSSParams& parameters, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);

    BigInt sigInt = BigInt("0x" + signature.toHex());
    BigInt decryptedHash = rawSignatureVer(sigInt, recipientPublicKey);

    size_t modulusSizeInBytes = keyPair.getModulusBitLength() / 8;
    std::string hexString = decryptedHash.toHexString();
    size_t expectedHexLength = modulusSizeInBytes * 2; // 2 hex digits per byte

    // Pad with leading zeros
    if (hexString.length() < expectedHexLength) {
        hexString = std::string(expectedHexLength - hexString.length(), '0') + hexString;
    }

    return verifyPSS_Padding(SecureBytes::fromHex(hexString), messageHash, parameters, modulusSizeInBytes);
}

SecureBytes RSA::encrypt(const SecureBytes& plaintext, const RSAPublicKey& recipientPublicKey, const PKCS1v15Params&) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = encodeForEncryptionPKCS1v15(plaintext, k);
    BigInt x = "0x" + padded.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawEncrypt(x, recipientPublicKey).toHexString()));
}

SecureBytes RSA::decrypt(const SecureBytes& ciphertext, const PKCS1v15Params&) {
    BigInt y = "0x" + ciphertext.toHex();
    BigInt result = rawDecrypt(y);
    size_t k = keyPair.getModulusBitLength() / 8;
    std::string hexString = result.toHexString();
    if (hexString.length() < k * 2)
        hexString = std::string(k * 2 - hexString.length(), '0') + hexString;
    return decodeForEncryptionPKCS1v15(SecureBytes::fromHex(hexString), k);
}

SecureBytes RSA::signMessage(const SecureBytes& message, const PKCS1v15Params& parameters) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = encodeForSigningPKCS1v15(message, parameters.hashAlg, k);
    BigInt x = "0x" + padded.toHex();
    return SecureBytes::fromHex(padToEvenHex(rawSignatureGen(x).toHexString()));
}

bool RSA::verifySignature(const SecureBytes& message, const SecureBytes& signature, const RSAPublicKey& recipientPublicKey, const PKCS1v15Params& parameters) {
    BigInt sigInt = "0x" + signature.toHex();
    BigInt decrypted = rawSignatureVer(sigInt, recipientPublicKey);
    size_t k = keyPair.getModulusBitLength() / 8;
    std::string hexString = decrypted.toHexString();
    if (hexString.length() < k * 2)
        hexString = std::string(k * 2 - hexString.length(), '0') + hexString;
    return verifyForSigningPKCS1v15(message, SecureBytes::fromHex(hexString), parameters.hashAlg);
}
