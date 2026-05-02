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
    // TODO: Use atleast v5 GMP for this secure function (mpz_powm_sec)
    return plaintext.modPow(recipientPublicKey.e, recipientPublicKey.n);
}

BigInt RSA::rawDecrypt(const BigInt& ciphertext) const {
    const RSAPrivateKey& priv = keyPair.privateKey;

    // Check if CRT values are available (e.g., dP, dQ, p, q)
    if (!priv.dP.isZero() && !priv.dQ.isZero() && !priv.p.isZero() && !priv.q.isZero()) {
        // CRT-based decryption
        // TODO: Use atleast v5 GMP for this secure function (mpz_powm_sec)
        BigInt m1 = ciphertext.modPow(priv.dP, priv.p);
        BigInt m2 = ciphertext.modPow(priv.dQ, priv.q);
        BigInt h  = (priv.qInv * (m1 - m2)) % priv.p;
        return m2 + (h * priv.q);
    }

    // Standard RSA decryption without CRT
    // TODO: Use atleast v5 GMP for this secure function (mpz_powm_sec)
    return ciphertext.modPow(priv.d, keyPair.publicKey.n);
}

BigInt RSA::rawSignatureGen(const BigInt& messageHash) const {
    // Signature generation is the same as raw decryption using the private key.
    return rawDecrypt(messageHash);
}

BigInt RSA::rawSignatureVer(const BigInt& signature, const RSAPublicKey& recipientPublicKey) const {
    // Signature verification is the same as raw encryption using the public key.
    return rawEncrypt(signature, recipientPublicKey);
}

// Serializes a BigInt as big-endian bytes zero-padded to targetLen bytes.
static SecureBytes bigIntToSecureBytes(const BigInt& x, size_t targetLen) {
    std::vector<uint8_t> raw = x.toBytes();
    if (raw.size() >= targetLen) return SecureBytes::fromVector(raw);
    std::vector<uint8_t> padded(targetLen, 0);
    std::copy(raw.begin(), raw.end(), padded.begin() + (targetLen - raw.size()));
    return SecureBytes::fromVector(padded);
}

SecureBytes RSA::encrypt(const SecureBytes& plaintext, const RSAPublicKey& recipientPublicKey) {
    size_t k = keyPair.getModulusBitLength() / 8;
    BigInt x = BigInt::fromBytes(plaintext.data(), plaintext.size());
    return bigIntToSecureBytes(rawEncrypt(x, recipientPublicKey), k);
}

SecureBytes RSA::encrypt(const SecureBytes& plaintext, const RSAPublicKey& recipientPublicKey, const OAEPParams& parameters) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = applyOAEP_Padding(plaintext, parameters, k);
    BigInt x = BigInt::fromBytes(padded.data(), padded.size());
    return bigIntToSecureBytes(rawEncrypt(x, recipientPublicKey), k);
}

SecureBytes RSA::decrypt(const SecureBytes& ciphertext) {
    BigInt y = BigInt::fromBytes(ciphertext.data(), ciphertext.size());
    return SecureBytes::fromVector(rawDecrypt(y).toBytes());
}

SecureBytes RSA::decrypt(const SecureBytes& ciphertext, const OAEPParams& parameters) {
    size_t k = keyPair.getModulusBitLength() / 8;
    BigInt y = BigInt::fromBytes(ciphertext.data(), ciphertext.size());
    return removeOAEP_Padding(bigIntToSecureBytes(rawDecrypt(y), k), parameters, k);
}

SecureBytes RSA::signMessage(const SecureBytes& message, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt x = BigInt::fromBytes(messageHash.data(), messageHash.size());
    return SecureBytes::fromVector(rawSignatureGen(x).toBytes());
}

SecureBytes RSA::signMessage(const SecureBytes& message, const PSSParams& parameters, HashAlgorithm hashAlg) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes messageHash = hash(hashAlg)(message);
    SecureBytes padded = encodePSS_Padding(messageHash, parameters, k);
    BigInt x = BigInt::fromBytes(padded.data(), padded.size());
    return bigIntToSecureBytes(rawSignatureGen(x), k);
}

bool RSA::verifySignature(const SecureBytes& message, const SecureBytes& signature, const RSAPublicKey& recipientPublicKey, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt sigInt = BigInt::fromBytes(signature.data(), signature.size());
    BigInt decryptedHash = rawSignatureVer(sigInt, recipientPublicKey);
    return decryptedHash == BigInt::fromBytes(messageHash.data(), messageHash.size());
}

bool RSA::verifySignature(const SecureBytes& message, const SecureBytes& signature, const RSAPublicKey& recipientPublicKey, const PSSParams& parameters, HashAlgorithm hashAlg) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt sigInt = BigInt::fromBytes(signature.data(), signature.size());
    BigInt decryptedHash = rawSignatureVer(sigInt, recipientPublicKey);
    return verifyPSS_Padding(bigIntToSecureBytes(decryptedHash, k), messageHash, parameters, k);
}

SecureBytes RSA::encrypt(const SecureBytes& plaintext, const RSAPublicKey& recipientPublicKey, const PKCS1v15Params&) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = encodeForEncryptionPKCS1v15(plaintext, k);
    BigInt x = BigInt::fromBytes(padded.data(), padded.size());
    return bigIntToSecureBytes(rawEncrypt(x, recipientPublicKey), k);
}

SecureBytes RSA::decrypt(const SecureBytes& ciphertext, const PKCS1v15Params&) {
    size_t k = keyPair.getModulusBitLength() / 8;
    BigInt y = BigInt::fromBytes(ciphertext.data(), ciphertext.size());
    return decodeForEncryptionPKCS1v15(bigIntToSecureBytes(rawDecrypt(y), k), k);
}

SecureBytes RSA::signMessage(const SecureBytes& message, const PKCS1v15Params& parameters) {
    size_t k = keyPair.getModulusBitLength() / 8;
    SecureBytes padded = encodeForSigningPKCS1v15(message, parameters.hashAlg, k);
    BigInt x = BigInt::fromBytes(padded.data(), padded.size());
    return bigIntToSecureBytes(rawSignatureGen(x), k);
}

bool RSA::verifySignature(const SecureBytes& message, const SecureBytes& signature, const RSAPublicKey& recipientPublicKey, const PKCS1v15Params& parameters) {
    size_t k = keyPair.getModulusBitLength() / 8;
    BigInt sigInt = BigInt::fromBytes(signature.data(), signature.size());
    BigInt decrypted = rawSignatureVer(sigInt, recipientPublicKey);
    return verifyForSigningPKCS1v15(message, bigIntToSecureBytes(decrypted, k), parameters.hashAlg);
}
