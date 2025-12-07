/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
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

std::vector<uint8_t> DEREncoder::encodeRSAPublicKeyToDER(const RSAPublicKey& key, KeyFormat format) {
    if (format == KeyFormat::PKCS1) {
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
std::vector<uint8_t> DEREncoder::encodeRSAPrivateKeyToDER(const RSAKeyPair& keyPair, KeyFormat format) {
    if (format == KeyFormat::PKCS1) {
        return encodeRSAPrivateKeyToPKCS1(keyPair);
    } else {
        return encodeRSAPrivateKeyToPKCS8(keyPair);
    }
}
