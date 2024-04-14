/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.cpp
 *
 * This file contains the implementation of Gestalts ECDSA security functions.
 */

#include <cmath>

#include <gestalt/ecdsa.h>
#include "infint/InfInt.h"
#include "utils.h"

KeyPair ECDSA::generateKeyPair() {
    InfInt privateKey = ecc.getRandomNumber(1, ecc.curve.n - 1);
    Point publicKey = ecc.scalarMultiplyPoints(privateKey, ecc.curve.basePoint, ecc.curve.n);
    return {publicKey, privateKey};
}

KeyPair ECDSA::setKeyPair(const InfInt& privateKey) {
    InfInt priv = privateKey;
    Point publicKey = ecc.scalarMultiplyPoints(priv, ecc.curve.basePoint, ecc.curve.n);
    return {publicKey, priv};
}

Signature ECDSA::signMessage(const std::string& message, const KeyPair& keyPair) {
    InfInt hashLen = message.length() * 4;
    size_t orderBitLength = 256;
    std::string E;
    std::string binaryHash = hexToBinary(message);

    if (hashLen >= orderBitLength) {
        E = binaryHash;
    } else {
        E = binaryHash.substr(0, orderBitLength);
    }

    InfInt e = binaryToInt(E);
    InfInt expectedHashToInt = "31062874186025896864030657271587873305428623785552478574175996069861246889046";
    if (e != expectedHashToInt) {
        std::cout << "e != expectedHashToInt" << std::endl;
        std::cout << "e = " << e << std::endl;
        std::cout << "expectedHashToInt = " << expectedHashToInt << std::endl;
    }

    //e = expectedHashToInt;
    e = "aaa";

    Signature S;
    //InfInt k = ecc.getRandomNumber(0, ecc.curve.n);
    InfInt k = "67228059374187986264907871817984995299114694677537144137068659840319595636958";
    Point R = ecc.scalarMultiplyPoints(k, ecc.curve.basePoint, ecc.curve.n);
    Point expectedR = {"47760720287736789683069083573948166072371263571273732180050208132677181355037", 
                       "100466561428796168350696032557296348669319250048870008168627029577169891763614"};
    
    if(R.x != expectedR.x) {
        std::cout << "R.x != expectedR.x" << std::endl;
        std::cout << "R.x = " << R.x << std::endl;
        std::cout << "expectedR.x = " << expectedR.x << std::endl;
    }
    if(R.y != expectedR.y) {
        std::cout << "R.y != expectedR.y" << std::endl;
        std::cout << "R.y = " << R.y << std::endl;
        std::cout << "expectedR.y = " << expectedR.y << std::endl;
    }

    S.r = ecc.mod(R.x, ecc.curve.n);
    InfInt expectedSr = "47760720287736789683069083573948166072371263571273732180050208132677181355037";
    if (S.r != expectedSr) {
        std::cout << "S.r != expectedSr" << std::endl;
        std::cout << "S.r = " << S.r << std::endl;
        std::cout << "expectedSr = " << expectedSr << std::endl;
    }
    
    InfInt kInverse = ecc.modInverse(k, ecc.curve.n); 
    InfInt expectedKInverse = "3986726756471655249437155726316333562479149966873125054448806045147008571426";
    if (kInverse != expectedKInverse) {
        std::cout << "kInverse != expectedKInverse" << std::endl;
        std::cout << "kInverse = " << kInverse << std::endl;
        std::cout << "expectedKInverse = " << expectedKInverse << std::endl;
    }

    {
        //InfInt privPlusSr = keyPair.privateKey * S.r;
        //InfInt expectedPrivPlusSr = "";
    }

    S.s = ecc.mod(((e + (keyPair.privateKey * S.r)) * kInverse), ecc.curve.n);
    std::cout << "S.s = " << S.s << std::endl;
    return S;
}

bool ECDSA::verifySignature(const std::string& message, const Signature signature, const Point& publicKey) {
    InfInt sInverse = ecc.modInverse(signature.s, ecc.curve.n);
    //InfInt w = ecc.mod(sInverse, ecc.curve.n);
    InfInt e = hexStringToInt(message);
    std::cout << "e after hexStringToInt : " << e << std::endl;
    e = "21389652466847203915883536631875066917527356942852403593369130071306944748985";
    std::cout << "e after setting it : " << e << std::endl;
    InfInt u1 = ecc.mod(sInverse * e, ecc.curve.n);
    InfInt u2 = ecc.mod(sInverse * signature.r, ecc.curve.n);
    Point P = ecc.addPoints(ecc.scalarMultiplyPoints(u1, ecc.curve.basePoint, ecc.curve.n), ecc.scalarMultiplyPoints(u2, publicKey, ecc.curve.n));
    std::cout << "P.x : " << P.x << std::endl;
    std::cout << "P.y : " << P.y << std::endl;
    std::cout << "P.x mod n : " << ecc.mod(P.x, ecc.curve.n) << std::endl;
    std::cout << "P.y mod n : " << ecc.mod(P.y, ecc.curve.n) << std::endl;
    return signature.r == ecc.mod(P.x, ecc.curve.n);
}