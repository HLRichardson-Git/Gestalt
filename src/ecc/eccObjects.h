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
    mpz_t x, y;

    Point() { mpz_inits(x, y, NULL); }
    Point(const BigInt& bX, const BigInt& bY) {
        mpz_inits(x, y, NULL);
        mpz_set(x, bX.n);
        mpz_set(y, bY.n);
    }

    Point(const Point& other) {
        mpz_init_set(x, other.x);
        mpz_init_set(y, other.y);
    }

    Point(const mpz_t xVal, const mpz_t yVal) {
        mpz_inits(x, y, NULL);
        mpz_set(x, xVal);
        mpz_set(y, yVal);
    }

    void operator =(const Point& other) {
        mpz_set(this->x, other.x);
        mpz_set(this->y, other.y);
    }

    ~Point() {
        mpz_clear(x);
        mpz_clear(y);
    }

    Point setPoint(const BigInt& bX, const BigInt& bY) { return Point(bX, bY); };
};

#include "standardCurves.h"

class PublicKey {
private:
    Point point;
    StandardCurve curve;

    StandardCurve guessCurve(const Point& point) {
        size_t sizeInBytes = (mpz_sizeinbase(point.x, 2) + 7) / 8;
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

    bool modular_sqrt(const mpz_t n, const mpz_t p, mpz_t result) {
        // Only works if p ≡ 3 mod 4
        if (mpz_congruent_ui_p(p, 3, 4)) {
            mpz_t exp;
            mpz_init(exp);
            mpz_add_ui(exp, p, 1);
            mpz_fdiv_q_ui(exp, exp, 4);
            mpz_powm(result, n, exp, p);
            mpz_clear(exp);

            // Check if result^2 ≡ n mod p
            mpz_t check;
            mpz_init(check);
            mpz_powm_ui(check, result, 2, p);
            bool isValid = (mpz_cmp(check, n) == 0);
            mpz_clear(check);
            return isValid;
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
        mpz_t yMod2;
        mpz_init(yMod2);
        mpz_mod_ui(yMod2, point.y, 2);

        // Serialize x
        size_t count = (mpz_sizeinbase(point.x, 2) + 7) / 8;
        SecureBytes result(1 + count);
        result[0] = (mpz_cmp_ui(yMod2, 0) == 0) ? 0x02 : 0x03;
        mpz_export(result.data() + 1, nullptr, 1, 1, 1, 0, point.x);
        mpz_clear(yMod2);
        return result;
    }

    void importCompressed(const SecureBytes& compressedKey) {
        if (compressedKey.size() < 2) {
            throw std::invalid_argument("Invalid compressed key");
        }

        // Check the compression byte (first byte)
        uint8_t prefix = compressedKey[0];
        if (prefix != 0x02 && prefix != 0x03) {
            throw std::invalid_argument("Invalid compressed ECC key format");
        }

        Curve curve = getCurveParams(this->curve);
        mpz_t x, y, rhs;
        mpz_inits(x, y, rhs, nullptr);

        // Extract x coordinate (skip first byte)
        mpz_import(x, compressedKey.size() - 1, 1, 1, 1, 0, compressedKey.data() + 1);

        // Calculate y^2 = x^3 + ax + b mod p
        mpz_powm_ui(rhs, x, 3, curve.p);
        mpz_addmul(rhs, curve.a, x);
        mpz_add(rhs, rhs, curve.b);
        mpz_mod(rhs, rhs, curve.p);

        bool found = modular_sqrt(rhs, curve.p, y);
        if (!found) throw std::runtime_error("Failed to compute sqrt for compressed key");

        // Check compression byte to determine which y to use
        bool isOddCompression = (prefix == 0x03);
        if ((isOddCompression && mpz_even_p(y)) || (!isOddCompression && mpz_odd_p(y))) {
            mpz_sub(y, curve.p, y);
        }

        point = Point(x, y);
        mpz_clears(x, y, rhs, nullptr);
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
    mpz_t privateKey;
    ECDSAPublicKey publicKey;

    KeyPair() { mpz_init(privateKey); }
    KeyPair(const mpz_t& gmpPriv, const ECDSAPublicKey& strPub) {
        mpz_init(privateKey);
        mpz_set(privateKey, gmpPriv);
        publicKey = strPub;
    }

    KeyPair(const BigInt& priv, const ECDSAPublicKey& pub) {
        mpz_init(privateKey);
        mpz_set(privateKey, priv.n);
        publicKey = pub;
    }

    KeyPair(const KeyPair& other) {
        mpz_init_set(privateKey, other.privateKey);
        publicKey = other.publicKey;
    }

    void operator =(const KeyPair& R) {
        mpz_set(this->privateKey, R.privateKey);
        this->publicKey = R.publicKey;
    } 

    ~KeyPair() { mpz_clear(privateKey); }

    Point getPublicKey() const { return publicKey.getPublicKey(); };

    std::vector<uint8_t> toDER(EccKeyFormat format = EccKeyFormat::PKCS8) const;
    void fromDER(const std::vector<uint8_t>& der, EccKeyFormat format = EccKeyFormat::PKCS8);
    std::string toPEM(EccKeyFormat format = EccKeyFormat::PKCS8) const;
    void fromPEM(const std::string& pem, EccKeyFormat format = EccKeyFormat::PKCS8);
};

class Signature {
public:
    mpz_t r, s;

    Signature() { mpz_inits(r, s, NULL); }
    Signature(const BigInt& bR, const BigInt& bS) {
        mpz_inits(r, s, NULL);
        mpz_set(r, bR.n);
        mpz_set(s, bS.n);
    }

    Signature(const Signature& other) {
        mpz_init_set(r, other.r);
        mpz_init_set(s, other.s);
    }
    
    void operator =(const Signature& other) {
        mpz_set(this->r, other.r);
        mpz_set(this->s, other.s);
    }

    ~Signature() {
        mpz_clear(r);
        mpz_clear(s);
    }
};