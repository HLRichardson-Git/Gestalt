/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der_encoder.cpp
 * 
 * Implementation of DER encoder for RSA keys
 */

#include "der.h"
#include "utils.h"
#include "../object_identifiers.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm>

std::vector<uint8_t> DEREncoder::encodeBigIntToBytes(const BigInt& value) {
    // Get the number of bytes needed
    size_t byteCount = value.byteLength();
    
    if (byteCount == 0) {
        return {0x00};  // Zero is encoded as single byte
    }
    
    std::vector<uint8_t> bytes(byteCount);
    
    // Export the BigInt to bytes (big-endian)
    size_t count = 0;
    mpz_export(bytes.data(), &count, 1, sizeof(uint8_t), 1, 0, value.n);
    
    // Resize to actual exported length
    bytes.resize(count);
    
    return bytes;
}

std::vector<uint8_t> DEREncoder::encodeInteger(const BigInt& value) {
    std::vector<uint8_t> valueBytes = encodeBigIntToBytes(value);

    // BigInt/ GMP strips leading zeros, so when we pass a zero this is stripped. So, when the value is empty
    // this means we passed a zero and it was stripped. Thus, we manually add the zero byte.
    if (valueBytes.empty()) {
        valueBytes.push_back(0x00);
    }

    bool needsPadding = valueBytes[0] & 0x80;

    std::vector<uint8_t> result;
    result.push_back(0x02);  // INTEGER tag

    size_t contentLength = valueBytes.size() + (needsPadding ? 1 : 0);
    std::vector<uint8_t> lengthBytes = encodeLength(contentLength);
    result.insert(result.end(), lengthBytes.begin(), lengthBytes.end());

    if (needsPadding) {
        result.push_back(0x00);
    }

    result.insert(result.end(), valueBytes.begin(), valueBytes.end());

    return result;
}

std::vector<uint8_t> DEREncoder::encodeLength(size_t length) {
    std::vector<uint8_t> result;
    
    if (length < 128) {
        // Short form: length fits in 7 bits
        result.push_back(static_cast<uint8_t>(length));
    } else {
        // Long form: need multiple bytes
        // Count how many bytes we need
        size_t temp = length;
        size_t numBytes = 0;
        while (temp > 0) {
            numBytes++;
            temp >>= 8;
        }
        
        // First byte: 0x80 | number of length bytes
        result.push_back(0x80 | static_cast<uint8_t>(numBytes));
        
        // Encode length in big-endian
        for (size_t i = numBytes; i > 0; i--) {
            result.push_back(static_cast<uint8_t>((length >> ((i - 1) * 8)) & 0xFF));
        }
    }
    
    return result;
}

std::vector<uint8_t> DEREncoder::wrapInSequence(const std::vector<uint8_t>& content) {
    std::vector<uint8_t> out;
    
    // SEQUENCE tag
    out.push_back(0x30);

    // Encode length
    if (content.size() < 128) {
        out.push_back(static_cast<uint8_t>(content.size()));
    } else {
        // Long form
        size_t len = content.size();
        std::vector<uint8_t> lenBytes;

        while (len > 0) {
            lenBytes.insert(lenBytes.begin(), static_cast<uint8_t>(len & 0xFF));
            len >>= 8;
        }

        out.push_back(0x80 | static_cast<uint8_t>(lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }

    // Content
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

void DEREncoder::writeTag(uint8_t tag) {
    buffer.push_back(tag);
}

void DEREncoder::writeLength(size_t length) {
    std::vector<uint8_t> lengthBytes = encodeLength(length);
    buffer.insert(buffer.end(), lengthBytes.begin(), lengthBytes.end());
}

void DEREncoder::writeInteger(const BigInt& value) {
    std::vector<uint8_t> encoded = encodeInteger(value);
    buffer.insert(buffer.end(), encoded.begin(), encoded.end());
}

void DEREncoder::writeSequence(const std::vector<uint8_t>& content) {
    writeTag(0x30);  // SEQUENCE tag
    writeLength(content.size());
    buffer.insert(buffer.end(), content.begin(), content.end());
}

void DEREncoder::writeObjectIdentifier(const std::string& oidHex) {
    writeTag(0x06);  // OBJECT IDENTIFIER tag
    
    // Convert hex string to bytes
    std::vector<uint8_t> oidBytes;
    oidBytes.reserve(oidHex.length() / 2);
    for (size_t i = 0; i < oidHex.length(); i += 2) {
        std::string byteStr = oidHex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        oidBytes.push_back(byte);
    }
    
    writeLength(oidBytes.size());
    buffer.insert(buffer.end(), oidBytes.begin(), oidBytes.end());
}

void DEREncoder::writeNull() {
    writeTag(0x05);  // NULL tag
    writeLength(0);  // NULL has zero length
}

void DEREncoder::writeBitString(const std::vector<uint8_t>& data) {
    writeTag(0x03);  // BIT STRING tag
    
    // data here is expected to be: [unusedBitsByte, ...actualData...]
    writeLength(data.size());
    
    // Write payload (first byte should be unused bits)
    buffer.insert(buffer.end(), data.begin(), data.end());
}

void DEREncoder::validateRSAPublicKey(const RSAPublicKey& key) {
    const BigInt& modulus = key.n;
    const BigInt& exponent = key.e;
    
    // Check modulus is valid
    if (modulus.isZero()) {
        throw std::runtime_error("RSA modulus cannot be zero");
    }
    
    if (modulus.isEven()) {
        throw std::runtime_error("RSA modulus must be odd");
    }
    
    size_t modulusBits = modulus.bitLength();
    if (modulusBits < 512) {
        // warn for small modulus
        std::cerr << "Warning: RSA modulus is only " << modulusBits << " bits (2048+ recommended)" << std::endl;
    }
    
    // Check exponent is valid
    if (exponent < 3) {
        throw std::runtime_error("RSA exponent too small: must be at least 3");
    }
    
    if (exponent.isEven()) {
        throw std::runtime_error("RSA exponent must be odd");
    }
    
    if (exponent >= modulus) {
        throw std::runtime_error("RSA exponent must be less than modulus");
    }
}

std::vector<uint8_t> DEREncoder::encodeRSAPublicKeyToPKCS1(const RSAPublicKey& key) {
    validateRSAPublicKey(key);

    buffer.clear();
    
    // Encode the integers (these produce full INTEGER TLVs)
    std::vector<uint8_t> modulusEncoded = encodeInteger(key.n);
    std::vector<uint8_t> exponentEncoded = encodeInteger(key.e);
    
    // Build the sequence content
    std::vector<uint8_t> sequenceContent;
    sequenceContent.insert(sequenceContent.end(), modulusEncoded.begin(), modulusEncoded.end());
    sequenceContent.insert(sequenceContent.end(), exponentEncoded.begin(), exponentEncoded.end());
    
    // Wrap in SEQUENCE (this will write tag + length + content)
    writeSequence(sequenceContent);
    
    return buffer;
}

std::vector<uint8_t> DEREncoder::encodeRSAPublicKeyToPKCS8(const RSAPublicKey& key) {
    clear();
    validateRSAPublicKey(key);

    // Step 1 — Encode PKCS#1 key (SEQUENCE { INTEGER n, INTEGER e })
    std::vector<uint8_t> pkcs1Der;
    {
        DEREncoder tmp;
        tmp.encodeRSAPublicKeyToPKCS1(key);
        pkcs1Der = tmp.getBuffer();
    }

    // Step 2 — AlgorithmIdentifier = SEQUENCE { OID rsaEncryption, NULL }
    std::vector<uint8_t> algIdContent;
    {
        DEREncoder tmp;
        tmp.writeObjectIdentifier(OID_RSA);
        tmp.writeNull();
        algIdContent = tmp.getBuffer();
    }
    std::vector<uint8_t> algId = wrapInSequence(algIdContent);

    // Step 3 — BIT STRING that wraps the PKCS#1 structure
    std::vector<uint8_t> bitStringPayload;
    bitStringPayload.reserve(1 + pkcs1Der.size());
    bitStringPayload.push_back(0x00); // unused bits
    bitStringPayload.insert(bitStringPayload.end(), pkcs1Der.begin(), pkcs1Der.end());

    // Encode BIT STRING TLV (tag + length + payload)
    std::vector<uint8_t> bitString;
    {
        DEREncoder tmp;
        tmp.writeBitString(bitStringPayload);
        bitString = tmp.getBuffer();
    }

    // Step 4 — Build final PKCS#8 structure:
    std::vector<uint8_t> outerContent;
    outerContent.insert(outerContent.end(), algId.begin(), algId.end());
    outerContent.insert(outerContent.end(), bitString.begin(), bitString.end());

    buffer = wrapInSequence(outerContent);
    return buffer;
}

std::vector<uint8_t> DEREncoder::encodeRSAPublicKeyToDER(const RSAPublicKey& key, RsaKeyFormat format) {
    if (format == RsaKeyFormat::PKCS1) {
        return encodeRSAPublicKeyToPKCS1(key);
    } else {
        return encodeRSAPublicKeyToPKCS8(key);
    }
}

// Encode RSA private key (PKCS#1) from an RSAKeyPair
std::vector<uint8_t> DEREncoder::encodeRSAPrivateKeyToPKCS1(const RSAKeyPair& keyPair) {
    clear();

    const RSAPublicKey& pub = keyPair.getPublicKey();
    const RSAPrivateKey& priv = keyPair.getPrivateKey();

    std::vector<uint8_t> content;

    // version = 0
    std::vector<uint8_t> versionEncoded = encodeInteger(BigInt(0));
    content.insert(content.end(), versionEncoded.begin(), versionEncoded.end());

    // n, e, d, p, q, dP, dQ, qInv
    std::vector<uint8_t> modulusEncoded = encodeInteger(pub.n);
    content.insert(content.end(), modulusEncoded.begin(), modulusEncoded.end());

    std::vector<uint8_t> exponentEncoded = encodeInteger(pub.e);
    content.insert(content.end(), exponentEncoded.begin(), exponentEncoded.end());

    std::vector<uint8_t> dEncoded = encodeInteger(priv.d);
    content.insert(content.end(), dEncoded.begin(), dEncoded.end());

    std::vector<uint8_t> pEncoded = encodeInteger(priv.p);
    content.insert(content.end(), pEncoded.begin(), pEncoded.end());

    std::vector<uint8_t> qEncoded = encodeInteger(priv.q);
    content.insert(content.end(), qEncoded.begin(), qEncoded.end());

    std::vector<uint8_t> dPEncoded = encodeInteger(priv.dP);
    content.insert(content.end(), dPEncoded.begin(), dPEncoded.end());

    std::vector<uint8_t> dQEncoded = encodeInteger(priv.dQ);
    content.insert(content.end(), dQEncoded.begin(), dQEncoded.end());

    std::vector<uint8_t> qInvEncoded = encodeInteger(priv.qInv);
    content.insert(content.end(), qInvEncoded.begin(), qInvEncoded.end());

    // Wrap in SEQUENCE
    buffer = wrapInSequence(content);
    return buffer;
}

// Encode RSA private key (PKCS#8) from an RSAKeyPair
std::vector<uint8_t> DEREncoder::encodeRSAPrivateKeyToPKCS8(const RSAKeyPair& keyPair) {
    clear();

    // 1. Encode PKCS#1 DER
    std::vector<uint8_t> pkcs1Der = encodeRSAPrivateKeyToPKCS1(keyPair);

    // 2. AlgorithmIdentifier SEQUENCE
    std::vector<uint8_t> algIdContent;
    {
        DEREncoder tmp;
        tmp.writeObjectIdentifier(OID_RSA);
        tmp.writeNull();
        algIdContent = tmp.getBuffer(); // raw content
    }
    std::vector<uint8_t> algId = wrapInSequence(algIdContent);

    // 3. PrivateKey OCTET STRING
    std::vector<uint8_t> privKeyOctet;
    privKeyOctet.push_back(0x04); // OCTET STRING tag
    std::vector<uint8_t> lenEnc = encodeLength(pkcs1Der.size());
    privKeyOctet.insert(privKeyOctet.end(), lenEnc.begin(), lenEnc.end());
    privKeyOctet.insert(privKeyOctet.end(), pkcs1Der.begin(), pkcs1Der.end());

    // 4. Version INTEGER
    std::vector<uint8_t> versionBytes = encodeInteger(BigInt(0));

    // 5. Combine all for outer SEQUENCE
    std::vector<uint8_t> outerContent;
    outerContent.insert(outerContent.end(), versionBytes.begin(), versionBytes.end());
    outerContent.insert(outerContent.end(), algId.begin(), algId.end());
    outerContent.insert(outerContent.end(), privKeyOctet.begin(), privKeyOctet.end());

    // 6. Wrap in outer SEQUENCE
    buffer = wrapInSequence(outerContent);

    return buffer;
}

// Convenience wrapper to choose format
std::vector<uint8_t> DEREncoder::encodeRSAPrivateKeyToDER(const RSAKeyPair& keyPair, RsaKeyFormat format) {
    if (format == RsaKeyFormat::PKCS1) {
        return encodeRSAPrivateKeyToPKCS1(keyPair);
    } else {
        return encodeRSAPrivateKeyToPKCS8(keyPair);
    }
}

// ============================================================
// EC helpers
// ============================================================

std::string DEREncoder::curveToOid(StandardCurve curve) {
    switch (curve) {
        case StandardCurve::P192:     return OID_SECP192R1;
        case StandardCurve::P224:     return OID_SECP224R1;
        case StandardCurve::P256:     return OID_SECP256R1;
        case StandardCurve::P384:     return OID_SECP384R1;
        case StandardCurve::P521:     return OID_SECP521R1;
        case StandardCurve::secp256k1: return OID_SECP256K1;
        default: throw std::runtime_error("Unknown StandardCurve value");
    }
}

size_t DEREncoder::getFieldByteSize(StandardCurve curve) {
    switch (curve) {
        case StandardCurve::P192:     return 24;
        case StandardCurve::P224:     return 28;
        case StandardCurve::P256:     return 32;
        case StandardCurve::P384:     return 48;
        case StandardCurve::P521:     return 66;
        case StandardCurve::secp256k1: return 32;
        default: throw std::runtime_error("Unknown StandardCurve value");
    }
}

// Encode an EC field element as a fixed-width unsigned big-endian byte vector.
// Unlike DER INTEGER encoding, field elements are NOT prefixed with a zero pad byte
// for high-bit values — they are always exactly byteLen bytes, left-padded with zeros.
std::vector<uint8_t> DEREncoder::encodeFieldElement(const BigInt& val, size_t byteLen) {
    std::vector<uint8_t> bytes(byteLen, 0x00);
    size_t count = 0;
    mpz_export(bytes.data(), &count, 1, 1, 1, 0, val.n);
    // mpz_export writes 'count' bytes big-endian at the front of the buffer.
    // Right-justify them so the result is exactly byteLen bytes with zero padding on the left.
    if (count < byteLen) {
        std::copy_backward(bytes.begin(), bytes.begin() + count, bytes.end());
        std::fill(bytes.begin(), bytes.begin() + (byteLen - count), 0x00);
    }
    return bytes;
}

// ============================================================
// EC public key encoding
// ============================================================

// SEC1 "public key" encoding: uncompressed point bytes 0x04 || X || Y.
// This is the raw content placed inside a BIT STRING for PKCS8, or returned
// standalone for SEC1 format.
std::vector<uint8_t> DEREncoder::encodeECPublicKeyToSEC1(const ECCPublicKey& key) {
    clear();
    StandardCurve curve = key.getPublicKeyCurve();
    size_t fieldLen = getFieldByteSize(curve);
    Point pt = key.getPublicKey();

    std::vector<uint8_t> result;
    result.push_back(0x04);  // uncompressed point marker
    std::vector<uint8_t> xBytes = encodeFieldElement(pt.x, fieldLen);
    std::vector<uint8_t> yBytes = encodeFieldElement(pt.y, fieldLen);
    result.insert(result.end(), xBytes.begin(), xBytes.end());
    result.insert(result.end(), yBytes.begin(), yBytes.end());

    buffer = result;
    return buffer;
}

// PKCS8 SubjectPublicKeyInfo for EC:
// SEQUENCE {
//   SEQUENCE { OID id-ecPublicKey, OID curve }
//   BIT STRING { 0x00, 0x04, X, Y }
// }
std::vector<uint8_t> DEREncoder::encodeECPublicKeyToPKCS8(const ECCPublicKey& key) {
    clear();
    StandardCurve curve = key.getPublicKeyCurve();

    // AlgorithmIdentifier
    std::vector<uint8_t> algIdContent;
    {
        DEREncoder tmp;
        tmp.writeObjectIdentifier(OID_EC_PUBLIC_KEY);
        tmp.writeObjectIdentifier(curveToOid(curve));
        algIdContent = tmp.getBuffer();
    }
    std::vector<uint8_t> algId = wrapInSequence(algIdContent);

    // Uncompressed point
    std::vector<uint8_t> pointBytes = encodeECPublicKeyToSEC1(key);

    // BIT STRING wrapping the point
    std::vector<uint8_t> bitStringPayload;
    bitStringPayload.push_back(0x00);  // unused bits
    bitStringPayload.insert(bitStringPayload.end(), pointBytes.begin(), pointBytes.end());
    std::vector<uint8_t> bitString;
    {
        DEREncoder tmp;
        tmp.writeBitString(bitStringPayload);
        bitString = tmp.getBuffer();
    }

    std::vector<uint8_t> outerContent;
    outerContent.insert(outerContent.end(), algId.begin(), algId.end());
    outerContent.insert(outerContent.end(), bitString.begin(), bitString.end());

    buffer = wrapInSequence(outerContent);
    return buffer;
}

std::vector<uint8_t> DEREncoder::encodeECPublicKeyToDER(const ECCPublicKey& key, EccKeyFormat format) {
    if (format == EccKeyFormat::SEC1) {
        return encodeECPublicKeyToSEC1(key);
    } else {
        return encodeECPublicKeyToPKCS8(key);
    }
}

// ============================================================
// EC private key encoding
// ============================================================

// SEC1 ECPrivateKey:
// SEQUENCE {
//   INTEGER version (1)
//   OCTET STRING { raw private key bytes }
//   [0] EXPLICIT OID curve
//   [1] EXPLICIT BIT STRING { 0x00, 0x04, X, Y }
// }
std::vector<uint8_t> DEREncoder::encodeECPrivateKeyToSEC1(const ECCKeyPair& keyPair) {
    clear();
    StandardCurve curve = keyPair.publicKey.getPublicKeyCurve();
    size_t fieldLen = getFieldByteSize(curve);

    // version = 1
    std::vector<uint8_t> version = encodeInteger(BigInt(1));

    // private key OCTET STRING
    std::vector<uint8_t> privBytes = encodeFieldElement(keyPair.privateKey, fieldLen);
    std::vector<uint8_t> privOctet;
    privOctet.push_back(0x04);  // OCTET STRING tag
    std::vector<uint8_t> privLen = encodeLength(privBytes.size());
    privOctet.insert(privOctet.end(), privLen.begin(), privLen.end());
    privOctet.insert(privOctet.end(), privBytes.begin(), privBytes.end());

    // [0] EXPLICIT OID curve
    std::vector<uint8_t> oidBytes;
    {
        DEREncoder tmp;
        tmp.writeObjectIdentifier(curveToOid(curve));
        oidBytes = tmp.getBuffer();
    }
    std::vector<uint8_t> tag0;
    tag0.push_back(0xa0);  // context tag [0] constructed
    std::vector<uint8_t> tag0Len = encodeLength(oidBytes.size());
    tag0.insert(tag0.end(), tag0Len.begin(), tag0Len.end());
    tag0.insert(tag0.end(), oidBytes.begin(), oidBytes.end());

    // [1] EXPLICIT BIT STRING { uncompressed point }
    std::vector<uint8_t> pointBytes = encodeECPublicKeyToSEC1(keyPair.publicKey);
    std::vector<uint8_t> bitStringPayload;
    bitStringPayload.push_back(0x00);  // unused bits
    bitStringPayload.insert(bitStringPayload.end(), pointBytes.begin(), pointBytes.end());
    std::vector<uint8_t> bitString;
    {
        DEREncoder tmp;
        tmp.writeBitString(bitStringPayload);
        bitString = tmp.getBuffer();
    }
    std::vector<uint8_t> tag1;
    tag1.push_back(0xa1);  // context tag [1] constructed
    std::vector<uint8_t> tag1Len = encodeLength(bitString.size());
    tag1.insert(tag1.end(), tag1Len.begin(), tag1Len.end());
    tag1.insert(tag1.end(), bitString.begin(), bitString.end());

    std::vector<uint8_t> content;
    content.insert(content.end(), version.begin(), version.end());
    content.insert(content.end(), privOctet.begin(), privOctet.end());
    content.insert(content.end(), tag0.begin(), tag0.end());
    content.insert(content.end(), tag1.begin(), tag1.end());

    buffer = wrapInSequence(content);
    return buffer;
}

// PKCS8 PrivateKeyInfo for EC:
// SEQUENCE {
//   INTEGER version (0)
//   SEQUENCE { OID id-ecPublicKey, OID curve }
//   OCTET STRING { SEC1 ECPrivateKey DER }
// }
std::vector<uint8_t> DEREncoder::encodeECPrivateKeyToPKCS8(const ECCKeyPair& keyPair) {
    clear();
    StandardCurve curve = keyPair.publicKey.getPublicKeyCurve();

    // version = 0
    std::vector<uint8_t> version = encodeInteger(BigInt(0));

    // AlgorithmIdentifier
    std::vector<uint8_t> algIdContent;
    {
        DEREncoder tmp;
        tmp.writeObjectIdentifier(OID_EC_PUBLIC_KEY);
        tmp.writeObjectIdentifier(curveToOid(curve));
        algIdContent = tmp.getBuffer();
    }
    std::vector<uint8_t> algId = wrapInSequence(algIdContent);

    // SEC1 private key DER
    std::vector<uint8_t> sec1Der = encodeECPrivateKeyToSEC1(keyPair);

    // OCTET STRING wrapping the SEC1 structure
    std::vector<uint8_t> privOctet;
    privOctet.push_back(0x04);  // OCTET STRING tag
    std::vector<uint8_t> privLen = encodeLength(sec1Der.size());
    privOctet.insert(privOctet.end(), privLen.begin(), privLen.end());
    privOctet.insert(privOctet.end(), sec1Der.begin(), sec1Der.end());

    std::vector<uint8_t> outerContent;
    outerContent.insert(outerContent.end(), version.begin(), version.end());
    outerContent.insert(outerContent.end(), algId.begin(), algId.end());
    outerContent.insert(outerContent.end(), privOctet.begin(), privOctet.end());

    buffer = wrapInSequence(outerContent);
    return buffer;
}

std::vector<uint8_t> DEREncoder::encodeECPrivateKeyToDER(const ECCKeyPair& keyPair, EccKeyFormat format) {
    if (format == EccKeyFormat::SEC1) {
        return encodeECPrivateKeyToSEC1(keyPair);
    } else {
        return encodeECPrivateKeyToPKCS8(keyPair);
    }
}
