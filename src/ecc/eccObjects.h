/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccObjects.h
 *
 * This file contains data objects used in Elliptic Curve Cryptography.
 *
 */
#pragma once

#include <string>

#include "bigInt/bigInt.h"
#include "asn1/object_identifiers.h"
#include "utils.h"
#include <gestalt/secure_bytes.h>

class DEREncoder;
class DERDecoder;

class Point {
public:
    BigInt x, y;

    Point() = default;
    Point(const BigInt& bX, const BigInt& bY) : x(bX), y(bY) {}
    Point(const Point& other) = default;
    Point& operator=(const Point& other) = default;
    ~Point() = default;

    Point setPoint(const BigInt& bX, const BigInt& bY) { return Point(bX, bY); }
};

#include "standardCurves.h"

class PublicKey {
private:
    Point point;
    StandardCurve curve;

    StandardCurve guessCurve(const Point& point) {
        size_t sizeInBytes = point.x.byteLength();
        if (sizeInBytes == 32) {
            return StandardCurve::P256;
        } else if (sizeInBytes == 48) {
            return StandardCurve::P384;
        } else if (sizeInBytes == 66) {
            return StandardCurve::P521;
        } else {
            return StandardCurve::secp256k1;
        }
    }

    bool modular_sqrt(const BigInt& n, const BigInt& p, BigInt& result) {
        // Only works if p ≡ 3 mod 4
        if (p.isCongruent(3, 4)) {
            BigInt exp = (p + 1).floorDiv(4);
            result = n.modPow(exp, p);
            BigInt check = result.modPow(2UL, p);
            return check == n;
        }
        return false;  // For full generality, implement Tonelli-Shanks
    }

public:
    // Constructors
    PublicKey() : curve(StandardCurve::P256) {}
    PublicKey(const BigInt& bX, const BigInt& bY) : point(Point(bX, bY)) {
        curve = guessCurve(point);
    }
    PublicKey(const SecureBytes& compressedKey, const StandardCurve& curve) : curve(curve) {
        importCompressed(compressedKey);
    }
    PublicKey(const Point& publicKey) : point(publicKey) {
        curve = guessCurve(publicKey);
    }
    PublicKey(const Point& publicKey, const StandardCurve& curve) : point(publicKey), curve(curve) {}

    // Accessors
    Point getPublicKey() const { return point; }
    StandardCurve getPublicKeyCurve() const { return curve; }

    void setCurve(const StandardCurve& givenCurve) { curve = givenCurve; }

    std::vector<uint8_t> toDER(EccKeyFormat format = EccKeyFormat::PKCS8) const;
    void fromDER(const std::vector<uint8_t>& der, EccKeyFormat format = EccKeyFormat::PKCS8);
    std::string toPEM(EccKeyFormat format = EccKeyFormat::PKCS8) const;
    void fromPEM(const std::string& pem, EccKeyFormat format = EccKeyFormat::PKCS8);
  
    SecureBytes exportCompressed() const {
        auto xBytes = point.x.toBytes();
        SecureBytes result(1 + xBytes.size());
        result[0] = point.y.isOdd() ? 0x03 : 0x02;
        std::copy(xBytes.begin(), xBytes.end(), result.begin() + 1);
        return result;
    }

    void importCompressed(const SecureBytes& compressedKey) {
        if (compressedKey.size() < 2) {
            throw std::invalid_argument("Invalid compressed key");
        }

        uint8_t prefix = compressedKey[0];
        if (prefix != 0x02 && prefix != 0x03) {
            throw std::invalid_argument("Invalid compressed ECC key format");
        }

        Curve curve = getCurveParams(this->curve);
        BigInt x = BigInt::fromBytes(compressedKey.data() + 1, compressedKey.size() - 1);

        // Calculate y^2 = x^3 + ax + b mod p
        BigInt rhs = (x.modPow(3UL, curve.p) + curve.a * x + curve.b) % curve.p;

        BigInt y;
        bool found = modular_sqrt(rhs, curve.p, y);
        if (!found) throw std::runtime_error("Failed to compute sqrt for compressed key");

        bool isOddCompression = (prefix == 0x03);
        if ((isOddCompression && y.isEven()) || (!isOddCompression && y.isOdd())) {
            y = curve.p - y;
        }

        point = Point(x, y);
    }

};

class ECDSAPublicKey : public PublicKey{
public:
    ECDSAPublicKey() : PublicKey() {}
    ECDSAPublicKey(const BigInt& bX, const BigInt& bY) : PublicKey(bX, bY) {}
    ECDSAPublicKey(const SecureBytes& compressedKey, const StandardCurve& curve) : PublicKey(compressedKey, curve) {}
    ECDSAPublicKey(const Point& point) : PublicKey(point) {}
    ECDSAPublicKey(const Point& point, const StandardCurve& curve) : PublicKey(point, curve) {}
};

class ECDHPublicKey : public PublicKey{
public:
    ECDHPublicKey() : PublicKey() {}
    ECDHPublicKey(const BigInt& bX, const BigInt& bY) : PublicKey(bX, bY) {}
    ECDHPublicKey(const SecureBytes& compressedKey, const StandardCurve& curve) : PublicKey(compressedKey, curve) {}
    ECDHPublicKey(const Point& point) : PublicKey(point) {}
    ECDHPublicKey(const Point& point, const StandardCurve& curve) : PublicKey(point, curve) {}
};

class KeyPair {
public:
    BigInt privateKey;
    ECDSAPublicKey publicKey;

    KeyPair() = default;
    KeyPair(const BigInt& priv, const ECDSAPublicKey& pub) : privateKey(priv), publicKey(pub) {}
    KeyPair(const KeyPair& other) = default;
    KeyPair& operator=(const KeyPair& other) = default;
    ~KeyPair() = default;

    Point getPublicKey() const { return publicKey.getPublicKey(); };

    std::vector<uint8_t> toDER(EccKeyFormat format = EccKeyFormat::PKCS8) const;
    void fromDER(const std::vector<uint8_t>& der, EccKeyFormat format = EccKeyFormat::PKCS8);
    std::string toPEM(EccKeyFormat format = EccKeyFormat::PKCS8) const;
    void fromPEM(const std::string& pem, EccKeyFormat format = EccKeyFormat::PKCS8);
};

class Signature {
public:
    BigInt r, s;

    Signature() = default;
    Signature(const BigInt& bR, const BigInt& bS) : r(bR), s(bS) {}
    Signature(const Signature& other) = default;
    Signature& operator=(const Signature& other) = default;
    ~Signature() = default;
};