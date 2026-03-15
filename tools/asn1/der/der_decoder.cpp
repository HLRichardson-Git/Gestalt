/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * der_decoder.cpp
 * 
 */

#include "der.h"
#include "utils.h"
#include "../object_identifiers.h"

#include <iostream>
#include <iomanip>
#include <sstream>

uint8_t DERDecoder::readTag() {
    if (pos >= data.size()) {
        throw std::runtime_error("Unexpected end of DER data at position " + std::to_string(pos));
    }
    return data[pos++];
}

size_t DERDecoder::readSequence() {
    uint8_t tag = readTag();
    if (tag != 0x30) {
        std::stringstream ss;
        ss << "Expected SEQUENCE tag (0x30) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }
    
    size_t length = readLength();
    size_t sequenceEnd = pos + length;
    
    // Validate sequence doesn't extend past data
    if (sequenceEnd > data.size()) {
        throw std::runtime_error("SEQUENCE length (" + std::to_string(length) + 
                                 ") exceeds available data at position " + 
                                 std::to_string(pos));
    }
    
    return sequenceEnd;
}

std::string DERDecoder::readObjectIdentifier() {
    uint8_t tag = readTag();
    if (tag != 0x06) {
        std::stringstream ss;
        ss << "Expected OBJECT IDENTIFIER tag (0x06) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    
    // Validate we have enough data
    if (pos + length > data.size()) {
        throw std::runtime_error("OID length exceeds available data");
    }
    
    std::string objectIdentifier;
    for (size_t i = 0; i < length; i++) {
        objectIdentifier.push_back(data[pos++]);
    }

    return bytesToHex(objectIdentifier);
}

bool DERDecoder::isValidRSAOid(const std::string& oid) {
    return oid == OID_RSA_ENCRYPTION || 
           oid == OID_RSA_SSA_PSS || 
           oid == OID_RSA_OAEP;
}

void DERDecoder::expectRSAObjectIdentifier() {
    std::string actualOid = readObjectIdentifier();
    
    if (!isValidRSAOid(actualOid)) {
        throw std::runtime_error(
            "Expected RSA OID (rsaEncryption, RSASSA-PSS, or RSA-OAEP), got: " + actualOid
        );
    }
}

void DERDecoder::readNullIfPresent() {
    // Check if next byte is NULL tag
    if (pos >= data.size()) {
        return; // No more data, NULL is optional
    }
    
    if (data[pos] == 0x05) {
        readNull();
    }
    // If not NULL, it's optional and we continue
}

void DERDecoder::readNull() {
    uint8_t tag = readTag();
    if (tag != 0x05) {
        std::stringstream ss;
        ss << "Expected NULL tag (0x05) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    if (length != 0) {
        throw std::runtime_error("Invalid NULL length: " + std::to_string(length) + 
                                 " (expected 0)");
    }
}

void DERDecoder::readBitString() {
    uint8_t tag = readTag();
    if (tag != 0x03) {
        std::stringstream ss;
        ss << "Expected BIT STRING tag (0x03) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    if (length == 0) {
        throw std::runtime_error("Invalid BIT STRING length: 0");
    }
    
    // Validate we have enough data
    if (pos + length > data.size()) {
        throw std::runtime_error("BIT STRING length exceeds available data");
    }

    uint8_t unusedBits = data[pos++];
    
    // Most RSA keys have 0 unused bits, but up to 7 is technically valid
    if (unusedBits > 7) {
        throw std::runtime_error("Invalid unused bits in BIT STRING: " + 
                                 std::to_string(unusedBits) + " (max 7)");
    }
    
    // For RSA public keys, we typically expect 0 unused bits
    if (unusedBits != 0) {
        std::cerr << "Warning: BIT STRING has " << (int)unusedBits 
                  << " unused bits (unusual for RSA keys)" << std::endl;
    }
}

size_t DERDecoder::readLength() {
    if (pos >= data.size()) {
        throw std::runtime_error("Unexpected end of DER data while reading length");
    }
    
    uint8_t lenByte = data[pos++];
    
    if (lenByte & 0x80) { // Long form
        size_t lengthBytes = lenByte & 0x7F;
        
        // Validate length encoding
        if (lengthBytes == 0) {
            throw std::runtime_error("Invalid indefinite length encoding");
        }
        
        if (lengthBytes > sizeof(size_t)) {
            throw std::runtime_error("Length field too large: " + 
                                     std::to_string(lengthBytes) + " bytes");
        }
        
        // Check we have enough bytes for the length
        if (pos + lengthBytes > data.size()) {
            throw std::runtime_error("Insufficient data for length field");
        }
        
        size_t length = 0;
        for (size_t i = 0; i < lengthBytes; i++) {
            length = (length << 8) | data[pos++];
        }
        
        // Validate DER requires minimal encoding (no leading zeros in long form)
        if (lengthBytes > 1 && length < 128) {
            throw std::runtime_error("Non-minimal length encoding");
        }
        
        return length;
    } else { // Short form
        return lenByte;
    }
}

void DERDecoder::printDerAtPosition() {
    for (size_t i = pos; i < data.size(); ++i) {
        std::cout << std::setw(2) << std::setfill('0')
                  << std::hex << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
}

BigInt DERDecoder::readIntegerAsBigInt() {
    uint8_t tag = readTag();
    if (tag != 0x02) {
        std::stringstream ss;
        ss << "Expected INTEGER tag (0x02) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }

    size_t length = readLength();
    if (length == 0) {
        throw std::runtime_error("INTEGER length cannot be zero");
    }
    
    // Validate we have enough data
    if (pos + length > data.size()) {
        throw std::runtime_error("INTEGER length exceeds available data");
    }
    
    // Check for negative integers (shouldn't happen in public keys)
    if (data[pos] & 0x80 && !(data[pos] == 0x00 && length > 1)) {
        throw std::runtime_error("Negative INTEGER detected (invalid for RSA public key)");
    }
    
    std::vector<uint8_t> integerBytes;
    
    // DER encoding adds a leading 0x00 for positive integers with high bit set
    bool hasPadding = (data[pos] == 0x00 && length > 1);
    
    if (hasPadding) {
        // Check for multiple padding bytes (DER violation)
        if (length > 2 && data[pos + 1] == 0x00) {
            throw std::runtime_error("Multiple leading zero bytes in INTEGER (non-minimal encoding)");
        }
        
        // Check that padding was necessary (next byte should have high bit set)
        if (!(data[pos + 1] & 0x80)) {
            throw std::runtime_error("Unnecessary leading zero byte in INTEGER");
        }
        
        pos++; // Skip the padding byte
        
        // Read remaining bytes
        for (size_t i = 0; i < length - 1; i++) {
            integerBytes.push_back(data[pos++]);
        }
    } else {
        // Read all bytes
        for (size_t i = 0; i < length; i++) {
            integerBytes.push_back(data[pos++]);
        }
    }
    
    // Validate integer isn't unreasonably large (e.g., > 16384 bits)
    if (integerBytes.size() > 2048) {
        throw std::runtime_error("INTEGER is unreasonably large: " + 
                                 std::to_string(integerBytes.size() * 8) + " bits");
    }

    return BigInt(integerBytes);
}

void DERDecoder::validateRSAPublicKey(const BigInt& modulus, const BigInt& exponent) {
    // Get bit lengths
    size_t modulusBits = modulus.bitLength();
    size_t exponentBits = exponent.bitLength();
    
    // Modulus should be at least 512 bits (though 2048+ is recommended)
    if (modulusBits < 512) {
        throw std::runtime_error("RSA modulus too small: " + std::to_string(modulusBits) + 
                                 " bits (minimum 512)");
    }
    
    // Warn about weak keys
    if (modulusBits < 2048) {
        std::cerr << "Warning: RSA modulus is only " << modulusBits 
                  << " bits (2048+ recommended)" << std::endl;
    }
    
    // Modulus should be odd (required for RSA)
    if (modulus.isEven()) {
        throw std::runtime_error("RSA modulus must be odd");
    }
    
    // Exponent should be at least 3
    if (exponent < 3) {
        throw std::runtime_error("RSA exponent too small: must be at least 3");
    }
    
    // Exponent must be odd (required for RSA)
    if (exponent.isEven()) {
        throw std::runtime_error("RSA exponent must be odd");
    }
    
    // Exponent should be less than modulus
    if (exponent >= modulus) {
        throw std::runtime_error("RSA exponent must be less than modulus");
    }
    
    // Common exponents are 3, 17, or 65537
    // Warn if using an unusual exponent
    if (exponent != 3 && exponent != 17 && exponent != 65537) {
        std::cerr << "Warning: Unusual RSA exponent detected" << std::endl;
    }
}

RSAPublicKey DERDecoder::decodeRSAPublicKeyFromPKCS8() {
    // PKCS#8 SubjectPublicKeyInfo structure
    size_t outerEnd = readSequence(); // Outer sequence
    size_t algIdEnd = readSequence(); // AlgorithmIdentifier sequence
    
    expectRSAObjectIdentifier();
    
    // NULL is optional in some encodings
    readNullIfPresent();
    
    // Validate we're still within AlgorithmIdentifier
    if (pos > algIdEnd) {
        throw std::runtime_error("Read past end of AlgorithmIdentifier");
    }
    
    readBitString(); // Bit string containing the PKCS#1 key
    readSequence(); // Inner PKCS#1 RSAPublicKey sequence

    // Parse the modulus (n) and exponent (e)
    BigInt modulus = readIntegerAsBigInt();
    BigInt exponent = readIntegerAsBigInt();
    
    // Validate the key parameters
    validateRSAPublicKey(modulus, exponent);
    
    // Validate we're at or near the end
    if (pos > outerEnd) {
        throw std::runtime_error("Read past end of outer SEQUENCE");
    }

    return RSAPublicKey(modulus, exponent);
}

RSAPublicKey DERDecoder::decodeRSAPublicKeyFromPKCS1() {
    // PKCS#1 RSAPublicKey structure
    size_t sequenceEnd = readSequence(); // Main sequence

    // Parse the modulus (n) and exponent (e) directly
    BigInt modulus = readIntegerAsBigInt();
    BigInt exponent = readIntegerAsBigInt();
    
    // Validate the key parameters
    validateRSAPublicKey(modulus, exponent);
    
    // Validate we're at the end of the sequence
    if (pos != sequenceEnd) {
        std::cerr << "Warning: Extra data at end of PKCS#1 key" << std::endl;
    }

    return RSAPublicKey(modulus, exponent);
}

RSAPublicKey DERDecoder::decodeRSAPublicKeyFromDER() {
    // Auto-detect format and parse accordingly
    size_t savedPos = pos;
    
    try {
        // Try PKCS#8 first (more common for public keys)
        return decodeRSAPublicKeyFromPKCS8();
    } catch (const std::runtime_error& e) {
        // Reset position and try PKCS#1
        pos = savedPos;
        try {
            return decodeRSAPublicKeyFromPKCS1();
        } catch (const std::runtime_error& e2) {
            throw std::runtime_error(
                "Failed to parse RSA public key. Not valid PKCS#8 or PKCS#1 format.\n"
                "PKCS#8 error: " + std::string(e.what()) + "\n" +
                "PKCS#1 error: " + std::string(e2.what())
            );
        }
    }
}

RSAKeyPair DERDecoder::decodeRSAPrivateKeyFromPKCS1() {
    size_t sequenceEnd = readSequence();

    BigInt version = readIntegerAsBigInt();
    if (version != 0) {
        std::cerr << "Warning: RSA private key version " 
                  << version.toDecimalString() << " (expected 0)" << std::endl;
    }

    BigInt n = readIntegerAsBigInt();
    BigInt e = readIntegerAsBigInt();
    BigInt d = readIntegerAsBigInt();

    // Build public key
    RSAPublicKey publicKey{n, e};

    // Full CRT-form private key
    BigInt p    = readIntegerAsBigInt();
    BigInt q    = readIntegerAsBigInt();
    BigInt dP   = readIntegerAsBigInt();
    BigInt dQ   = readIntegerAsBigInt();
    BigInt qInv = readIntegerAsBigInt();

    RSAPrivateKey privateKey(d, p, q, dP, dQ, qInv);

    if (pos != sequenceEnd) {
        std::cerr << "Warning: extra data at end of PKCS#1 private key" << std::endl;
    }

    return RSAKeyPair(privateKey, publicKey);
}

RSAKeyPair DERDecoder::decodeRSAPrivateKeyFromPKCS8() {
    size_t outerEnd = readSequence();  // Outer PrivateKeyInfo sequence
    
    // Read version (should be 0)
    BigInt version = readIntegerAsBigInt();
    if (version != 0) {
        std::cerr << "Warning: PKCS#8 version is " 
                  << version.toDecimalString() << " (expected 0)" << std::endl;
    }
    
    // Read AlgorithmIdentifier
    size_t algIdEnd = readSequence();
    expectRSAObjectIdentifier();
    readNullIfPresent();  // Parameters are optional
    
    // Validate we're at the end of AlgorithmIdentifier
    if (pos > algIdEnd) {
        throw std::runtime_error("Read past end of AlgorithmIdentifier");
    }
    
    // Read the OCTET STRING containing the PKCS#1 private key
    uint8_t tag = readTag();
    if (tag != 0x04) {
        std::stringstream ss;
        ss << "Expected OCTET STRING tag (0x04), got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }
    
    size_t octetStringLength = readLength();
    size_t octetStringEnd = pos + octetStringLength;
    
    // Validate length
    if (octetStringEnd > data.size()) {
        throw std::runtime_error("OCTET STRING length exceeds available data");
    }
    
    // The OCTET STRING contains a PKCS#1 RSAPrivateKey
    // We parse it in place since pos is already pointing to the start
    RSAKeyPair key = decodeRSAPrivateKeyFromPKCS1();
    
    // Validate we're at the end of the OCTET STRING
    if (pos != octetStringEnd) {
        std::cerr << "Warning: Extra data in PKCS#8 OCTET STRING" << std::endl;
    }
    
    // Validate we're at or near the end of the outer sequence
    if (pos > outerEnd) {
        throw std::runtime_error("Read past end of PKCS#8 PrivateKeyInfo");
    }
    
    return key;
}

RSAKeyPair DERDecoder::decodeRSAPrivateKeyFromDER() {
    size_t savedPos = pos;

    try {
        // Try PKCS#8 first (more common)
        return decodeRSAPrivateKeyFromPKCS8();
    } catch (const std::runtime_error& e) {
        // Reset position and try PKCS#1
        pos = savedPos;
        try {
            return decodeRSAPrivateKeyFromPKCS1();
        } catch (const std::runtime_error& e2) {
            throw std::runtime_error(
                "Failed to parse RSA private key. Not valid PKCS#8 or PKCS#1 format.\n"
                "PKCS#8 error: " + std::string(e.what()) + "\n" +
                "PKCS#1 error: " + std::string(e2.what())
            );
        }
    }
}

// ============================================================
// EC helpers
// ============================================================

StandardCurve DERDecoder::oidToCurve(const std::string& oid) {
    if (oid == OID_SECP192R1) return StandardCurve::P192;
    if (oid == OID_SECP224R1) return StandardCurve::P224;
    if (oid == OID_SECP256R1) return StandardCurve::P256;
    if (oid == OID_SECP384R1) return StandardCurve::P384;
    if (oid == OID_SECP521R1) return StandardCurve::P521;
    if (oid == OID_SECP256K1) return StandardCurve::secp256k1;
    throw std::runtime_error("Unknown EC curve OID: " + oid);
}

std::vector<uint8_t> DERDecoder::readOctetString() {
    uint8_t tag = readTag();
    if (tag != 0x04) {
        std::stringstream ss;
        ss << "Expected OCTET STRING tag (0x04) at position " << (pos - 1)
           << ", got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }
    size_t length = readLength();
    if (pos + length > data.size()) {
        throw std::runtime_error("OCTET STRING length exceeds available data");
    }
    std::vector<uint8_t> bytes(data.begin() + pos, data.begin() + pos + length);
    pos += length;
    return bytes;
}

// Parse raw uncompressed EC point bytes: 0x04 || X || Y
// (No outer DER tag — these are the payload bytes from a BIT STRING or standalone)
static ECDSAPublicKey parseUncompressedPoint(const std::vector<uint8_t>& pointBytes) {
    if (pointBytes.empty() || pointBytes[0] != 0x04) {
        throw std::runtime_error("Expected uncompressed EC point (0x04 prefix)");
    }
    size_t coordLen = (pointBytes.size() - 1) / 2;
    if (pointBytes.size() != 1 + 2 * coordLen) {
        throw std::runtime_error("Invalid EC point length");
    }

    Point pt;
    mpz_import(pt.x, coordLen, 1, 1, 1, 0, pointBytes.data() + 1);
    mpz_import(pt.y, coordLen, 1, 1, 1, 0, pointBytes.data() + 1 + coordLen);
    return ECDSAPublicKey(pt);
}

// ============================================================
// EC public key decoding
// ============================================================

// SEC1 public key: raw uncompressed point bytes 0x04 || X || Y (no outer DER wrapper)
ECDSAPublicKey DERDecoder::decodeECPublicKeyFromSEC1() {
    if (pos >= data.size() || data[pos] != 0x04) {
        throw std::runtime_error("Expected uncompressed EC point (0x04) for SEC1 public key");
    }
    std::vector<uint8_t> pointBytes(data.begin() + pos, data.end());
    pos = data.size();
    return parseUncompressedPoint(pointBytes);
}

// PKCS8 SubjectPublicKeyInfo:
// SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID curve }, BIT STRING { 0x00, 0x04, X, Y } }
ECDSAPublicKey DERDecoder::decodeECPublicKeyFromPKCS8() {
    size_t outerEnd = readSequence();
    size_t algIdEnd = readSequence();

    std::string algOid = readObjectIdentifier();
    if (algOid != OID_EC_PUBLIC_KEY) {
        throw std::runtime_error("Expected id-ecPublicKey OID, got: " + algOid);
    }

    std::string curveOid = readObjectIdentifier();
    StandardCurve curve = oidToCurve(curveOid);

    if (pos > algIdEnd) {
        throw std::runtime_error("Read past end of AlgorithmIdentifier");
    }
    pos = algIdEnd;  // skip any trailing parameters

    // BIT STRING containing the uncompressed point
    uint8_t tag = readTag();
    if (tag != 0x03) {
        std::stringstream ss;
        ss << "Expected BIT STRING (0x03), got: 0x" << std::hex << (int)tag;
        throw std::runtime_error(ss.str());
    }
    size_t bitStringLen = readLength();
    if (pos + bitStringLen > data.size()) {
        throw std::runtime_error("BIT STRING length exceeds available data");
    }
    uint8_t unusedBits = data[pos++];
    if (unusedBits != 0) {
        throw std::runtime_error("Non-zero unused bits in EC public key BIT STRING");
    }
    std::vector<uint8_t> pointBytes(data.begin() + pos, data.begin() + pos + bitStringLen - 1);
    pos += bitStringLen - 1;

    ECDSAPublicKey pubKey = parseUncompressedPoint(pointBytes);
    pubKey.setCurve(curve);

    if (pos > outerEnd) {
        throw std::runtime_error("Read past end of SubjectPublicKeyInfo");
    }
    return pubKey;
}

ECDSAPublicKey DERDecoder::decodeECPublicKeyFromDER() {
    size_t savedPos = pos;
    try {
        return decodeECPublicKeyFromPKCS8();
    } catch (const std::runtime_error& e) {
        pos = savedPos;
        try {
            return decodeECPublicKeyFromSEC1();
        } catch (const std::runtime_error& e2) {
            throw std::runtime_error(
                "Failed to parse EC public key. Not valid PKCS8 or SEC1 format.\n"
                "PKCS8 error: " + std::string(e.what()) + "\n" +
                "SEC1 error: " + std::string(e2.what())
            );
        }
    }
}

// ============================================================
// EC private key decoding
// ============================================================

// SEC1 ECPrivateKey:
// SEQUENCE { INTEGER version(1), OCTET STRING priv, [0] OID curve, [1] BIT STRING pubKey }
KeyPair DERDecoder::decodeECPrivateKeyFromSEC1() {
    size_t seqEnd = readSequence();

    // version must be 1
    BigInt version = readIntegerAsBigInt();
    if (version != 1) {
        std::cerr << "Warning: EC SEC1 private key version "
                  << version.toDecimalString() << " (expected 1)" << std::endl;
    }

    // private key OCTET STRING (raw field element bytes)
    std::vector<uint8_t> privBytes = readOctetString();

    // [0] EXPLICIT OID curve (optional but always written by this encoder)
    StandardCurve curve = StandardCurve::secp256k1;
    if (pos < seqEnd && data[pos] == 0xa0) {
        pos++;  // consume context tag
        size_t tag0Len = readLength();
        size_t tag0End = pos + tag0Len;
        std::string curveOid = readObjectIdentifier();
        curve = oidToCurve(curveOid);
        pos = tag0End;
    }

    // [1] EXPLICIT BIT STRING public key (optional)
    ECDSAPublicKey pubKey;
    if (pos < seqEnd && data[pos] == 0xa1) {
        pos++;  // consume context tag
        size_t tag1Len = readLength();
        size_t tag1End = pos + tag1Len;
        // BIT STRING inside
        uint8_t bsTag = readTag();
        if (bsTag != 0x03) {
            throw std::runtime_error("Expected BIT STRING inside [1] context tag");
        }
        size_t bsLen = readLength();
        uint8_t unusedBits = data[pos++];
        if (unusedBits != 0) {
            throw std::runtime_error("Non-zero unused bits in EC public key BIT STRING");
        }
        std::vector<uint8_t> pointBytes(data.begin() + pos, data.begin() + pos + bsLen - 1);
        pos += bsLen - 1;
        pubKey = parseUncompressedPoint(pointBytes);
        pos = tag1End;
    }
    pubKey.setCurve(curve);

    // Import private key bytes into mpz_t
    KeyPair keyPair;
    mpz_import(keyPair.privateKey, privBytes.size(), 1, 1, 1, 0, privBytes.data());
    keyPair.publicKey = pubKey;

    return keyPair;
}

// PKCS8 PrivateKeyInfo for EC:
// SEQUENCE { INTEGER version(0), SEQUENCE { OID id-ecPublicKey, OID curve }, OCTET STRING { SEC1 } }
KeyPair DERDecoder::decodeECPrivateKeyFromPKCS8() {
    size_t outerEnd = readSequence();

    BigInt version = readIntegerAsBigInt();
    if (version != 0) {
        std::cerr << "Warning: PKCS8 version " << version.toDecimalString() << " (expected 0)" << std::endl;
    }

    size_t algIdEnd = readSequence();
    std::string algOid = readObjectIdentifier();
    if (algOid != OID_EC_PUBLIC_KEY) {
        throw std::runtime_error("Expected id-ecPublicKey OID, got: " + algOid);
    }
    std::string curveOid = readObjectIdentifier();
    StandardCurve curve = oidToCurve(curveOid);
    pos = algIdEnd;  // skip any trailing parameters

    // OCTET STRING containing the SEC1 ECPrivateKey
    std::vector<uint8_t> sec1Bytes = readOctetString();

    // Parse the SEC1 structure
    DERDecoder sec1Decoder(sec1Bytes);
    KeyPair keyPair = sec1Decoder.decodeECPrivateKeyFromSEC1();

    // The curve OID from PKCS8 is authoritative
    keyPair.publicKey.setCurve(curve);

    if (pos > outerEnd) {
        throw std::runtime_error("Read past end of PKCS8 PrivateKeyInfo");
    }
    return keyPair;
}

KeyPair DERDecoder::decodeECPrivateKeyFromDER() {
    size_t savedPos = pos;
    try {
        return decodeECPrivateKeyFromPKCS8();
    } catch (const std::runtime_error& e) {
        pos = savedPos;
        try {
            return decodeECPrivateKeyFromSEC1();
        } catch (const std::runtime_error& e2) {
            throw std::runtime_error(
                "Failed to parse EC private key. Not valid PKCS8 or SEC1 format.\n"
                "PKCS8 error: " + std::string(e.what()) + "\n" +
                "SEC1 error: " + std::string(e2.what())
            );
        }
    }
}