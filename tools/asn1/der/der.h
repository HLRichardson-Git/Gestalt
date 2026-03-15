/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der.h
 */

#pragma once

#include "rsa/rsa_key_generation/rsaKeyGen.h"
#include "ecc/eccObjects.h"
#include "../object_identifiers.h"

#include <vector>
#include <string>

class DERDecoder {
private:
    const std::vector<uint8_t> data;
    size_t pos;

    // Core DER reading methods
    size_t readSequence();
    void readBitString();
    void readNull();
    void readNullIfPresent();
    uint8_t readTag();
    size_t readLength();
    BigInt readIntegerAsBigInt();

    // OID handling methods
    std::string readObjectIdentifier();
    void expectRSAObjectIdentifier();  // Accepts any valid RSA OID
    bool isValidRSAOid(const std::string& oid);
    StandardCurve oidToCurve(const std::string& oid);

    // Raw byte reading
    std::vector<uint8_t> readOctetString();

    // Validation
    void validateRSAPublicKey(const BigInt& modulus, const BigInt& exponent);
    void validateRSAPrivateKey(const RSAPrivateKey& key);

public:
    explicit DERDecoder(std::vector<uint8_t> input)
        : data(std::move(input)), pos(0) {}

    void printDerAtPosition(); // For debugging

    // RSA public key decoding methods
    RSAPublicKey decodeRSAPublicKeyFromPKCS8();
    RSAPublicKey decodeRSAPublicKeyFromPKCS1();
    RSAPublicKey decodeRSAPublicKeyFromDER();  // Auto-detect

    // RSA private key decoding methods
    RSAKeyPair decodeRSAPrivateKeyFromPKCS1();
    RSAKeyPair decodeRSAPrivateKeyFromPKCS8();
    RSAKeyPair decodeRSAPrivateKeyFromDER();  // Auto-detect

    // EC public key decoding methods
    ECDSAPublicKey decodeECPublicKeyFromSEC1();
    ECDSAPublicKey decodeECPublicKeyFromPKCS8();
    ECDSAPublicKey decodeECPublicKeyFromDER();  // Auto-detect

    // EC private key decoding methods
    KeyPair decodeECPrivateKeyFromSEC1();
    KeyPair decodeECPrivateKeyFromPKCS8();
    KeyPair decodeECPrivateKeyFromDER();  // Auto-detect
};

class DEREncoder {
private:
    std::vector<uint8_t> buffer;

    // Core DER writing methods
    void writeTag(uint8_t tag);
    void writeLength(size_t length);
    void writeInteger(const BigInt& value);
    void writeSequence(const std::vector<uint8_t>& content);
    void writeObjectIdentifier(const std::string& oidHex);
    void writeNull();
    void writeBitString(const std::vector<uint8_t>& data);

    // Helper methods
    std::vector<uint8_t> encodeLength(size_t length);
    std::vector<uint8_t> encodeInteger(const BigInt& value);
    std::vector<uint8_t> encodeBigIntToBytes(const BigInt& value);
    std::vector<uint8_t> wrapInSequence(const std::vector<uint8_t>& content);
    const std::vector<uint8_t>& getBuffer() const { return buffer; }
    void clear() { buffer.clear(); }

    // EC helpers
    std::vector<uint8_t> encodeFieldElement(const mpz_t& val, size_t byteLen);
    std::string curveToOid(StandardCurve curve);
    size_t getFieldByteSize(StandardCurve curve);

    // Validation
    void validateRSAPublicKey(const RSAPublicKey& key);

public:
    DEREncoder() = default;

    // RSA public key encoding methods
    std::vector<uint8_t> encodeRSAPublicKeyToPKCS1(const RSAPublicKey& key);
    std::vector<uint8_t> encodeRSAPublicKeyToPKCS8(const RSAPublicKey& key);
    std::vector<uint8_t> encodeRSAPublicKeyToDER(const RSAPublicKey& key, RsaKeyFormat format = RsaKeyFormat::PKCS8);

    // RSA private key encoding methods
    std::vector<uint8_t> encodeRSAPrivateKeyToPKCS1(const RSAKeyPair& keyPair);
    std::vector<uint8_t> encodeRSAPrivateKeyToPKCS8(const RSAKeyPair& keyPair);
    std::vector<uint8_t> encodeRSAPrivateKeyToDER(const RSAKeyPair& keyPair, RsaKeyFormat format = RsaKeyFormat::PKCS8);

    // EC public key encoding methods (accept PublicKey& so ECDSAPublicKey and ECDHPublicKey both work)
    std::vector<uint8_t> encodeECPublicKeyToSEC1(const PublicKey& key);
    std::vector<uint8_t> encodeECPublicKeyToPKCS8(const PublicKey& key);
    std::vector<uint8_t> encodeECPublicKeyToDER(const PublicKey& key, EccKeyFormat format = EccKeyFormat::PKCS8);

    // EC private key encoding methods
    std::vector<uint8_t> encodeECPrivateKeyToSEC1(const KeyPair& keyPair);
    std::vector<uint8_t> encodeECPrivateKeyToPKCS8(const KeyPair& keyPair);
    std::vector<uint8_t> encodeECPrivateKeyToDER(const KeyPair& keyPair, EccKeyFormat format = EccKeyFormat::PKCS8);

};