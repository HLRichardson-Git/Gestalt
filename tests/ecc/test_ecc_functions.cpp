/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecc_functions.cpp
 *
 * This file containts the unit tests for the ECC (Elliptic Curve Cryptography) Gestalt arithmetic functions.
 * These tests cover various scenarios including point addition, doubling, and multiplication by a scalar.
 * The tests also include initialization and operations for the ECC objects created for Gestalt.
 *
 */

#include "gtest/gtest.h"

#include "ecc/ecc.h"
#include "utils.h"

class ECC_Test : public ::testing::Test {
private:
    ECC ecc;
protected:
    Point addPoints(Point P, Point Q) {return ecc.addPoints(P, Q);};
    Point doublePoint(Point P) {return ecc.doublePoint(P);};
    Point scalarMultiplyPoints(const BigInt& k, Point P) {return ecc.scalarMultiplyPoints(k, P);};
    BigInt fieldElementToInteger(const BigInt& fieldElement) { return ecc.fieldElementToInteger(fieldElement); };
    bool isInDomainRange(const BigInt& k) { return ecc.isInDomainRange(k); };
    bool isIdentityPoint(const Point& P) { return ecc.isIdentityPoint(P); };
    bool isPointOnCurve(const Point& P) { return ecc.isPointOnCurve(P); };
    std::string isValidPublicKey(const ECDSAPublicKey& P) { return ecc.isValidPublicKey(P); };
    std::string isValidKeyPair(const KeyPair& K) { return ecc.isValidKeyPair(K); };
};

TEST_F(ECC_Test, testPointAddition) {
    Point P(BigInt("0x1a9b50177520875bf4bdeea006703f39066bf2126a0e19695639ebd71d27890e"),
            BigInt("0x4db72d506fb060bca6b2fd5d5806d65e00b675d146cf3f89d93941612bf8dcb9"));
    Point Q(BigInt("0xd901df95be82c8953b83e569b9b63b0b52e6ee9a2e6fc400e852090e3f6fec69"),
            BigInt("0x99a666ff41bf66483e1fd92960b931df1effeb4465673c52cc011e4a0a803df3"));

    Point R = addPoints(P, Q);

    Point expected(BigInt("0x3be0eb288273201f90f975710f08f41076dd79587499283ad471f2f33a03c81"),
                   BigInt("0x328a64c3e38dc5e5b1734b91fae70425703c74e400d1740389a8424280d915b3"));

    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);
}

TEST_F(ECC_Test, identityPointAddition) {
    Point P(BigInt("0x1a9b50177520875bf4bdeea006703f39066bf2126a0e19695639ebd71d27890e"),
            BigInt("0x4db72d506fb060bca6b2fd5d5806d65e00b675d146cf3f89d93941612bf8dcb9"));
    Point Q;

    Point R = addPoints(P, Q);

    Point expected(BigInt("0x1a9b50177520875bf4bdeea006703f39066bf2126a0e19695639ebd71d27890e"),
                   BigInt("0x4db72d506fb060bca6b2fd5d5806d65e00b675d146cf3f89d93941612bf8dcb9"));

    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);
}

TEST_F(ECC_Test, testPointDouble) {
    Point P(BigInt("0x1a9b50177520875bf4bdeea006703f39066bf2126a0e19695639ebd71d27890e"),
            BigInt("0x4db72d506fb060bca6b2fd5d5806d65e00b675d146cf3f89d93941612bf8dcb9"));

    Point R = doublePoint(P);

    Point expected(BigInt("0x102effa403b27f4252a0c8d52522a54812b78646638e1e4ef9dcaf725c587f95"),
                   BigInt("0x8a556d2f948557616ed4b3360fa83f2fe43815a80375c2f8f35d5c0e94467750"));

    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);
}

TEST_F(ECC_Test, testPointMultiplication) {
    Point P(BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"),
            BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    BigInt N = "0x8";

    Point R = scalarMultiplyPoints(N, P);

    Point expected(BigInt("0x86a5ee3b95e14201a8dc231aedbf5b0c48b31d2f1e6ccee090a8d798dd37e896"),
                   BigInt("0x4c571310c823401a22185452f49473f315757896ac032cfcbdbc15b0cd74a422"));

    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);
}

TEST_F(ECC_Test, FieldElementToInteger) {
    BigInt fieldElement = "0x123456789ABCDEF";
    BigInt result = fieldElementToInteger(fieldElement);

    EXPECT_EQ(fieldElement, result);
}

TEST_F(ECC_Test, isInDomainRange) {
    BigInt P = "0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577";
    EXPECT_TRUE(isInDomainRange(P));

    BigInt Q = "-10";
    EXPECT_FALSE(isInDomainRange(Q));
}

TEST_F(ECC_Test, pointIsIdentiy) {
    Point P;
    EXPECT_TRUE(isIdentityPoint(P));

    Point Q(BigInt("0x1"), BigInt("0x1"));
    EXPECT_FALSE(isIdentityPoint(Q));
}

TEST_F(ECC_Test, pointIsOnCurve) {
    Point P(BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"),
            BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));
    EXPECT_TRUE(isPointOnCurve(P));

    Point Q(BigInt("-1000"), BigInt("56"));
    EXPECT_FALSE(isPointOnCurve(Q));
}

TEST_F(ECC_Test, isValidPublicKey) {
    ECDSAPublicKey validPublicKey(BigInt("0xffc5679a309953b590ef4a3601a5598e83893017527859dd6312ec1177f53749"),
                         BigInt("0xe8ba1c3fa2e5c9d3312e93361b08662d81cb540c1b08a7e0e17b1b5651462584"));
    std::cout << isValidPublicKey(validPublicKey) << std::endl;
    EXPECT_TRUE(isValidPublicKey(validPublicKey).empty());


    ECDSAPublicKey pointNotOnCurve(BigInt("-1000"), BigInt("56"));
    EXPECT_TRUE(isValidPublicKey(pointNotOnCurve) == "Error: Given Public Key is not on the curve.");

    ECDSAPublicKey pointIsIdentityPoint;
    EXPECT_TRUE(isValidPublicKey(pointIsIdentityPoint) == "Error: Given Public Key is the Identity element.");

    ECDSAPublicKey resultIsIdentity(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                           BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    BigInt modulus = "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    Point result = scalarMultiplyPoints(modulus, resultIsIdentity.getPublicKey());
    EXPECT_TRUE(result.x.isZero());
    EXPECT_TRUE(result.y.isZero());
}

TEST_F(ECC_Test, isValidKeyPair) {
    ECDSAPublicKey publicKey(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                    BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair validKeyPair(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"), publicKey);
    EXPECT_TRUE(isValidKeyPair(validKeyPair).empty());

    KeyPair invalidPrivateKey(BigInt("-1000"), publicKey);
    EXPECT_TRUE(isValidKeyPair(invalidPrivateKey) == "Error: Given Private Key is not in range [1, n - 1].");

    ECDSAPublicKey pubKeyIsNotPair(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                          BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair mismatchKeyPair(BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"), pubKeyIsNotPair);
    EXPECT_TRUE(isValidKeyPair(mismatchKeyPair) == "Error: Pair-wise consistency check failed.");
}

TEST_F(ECC_Test, setKeyPair) {
    // Uninitated is set to 0
    KeyPair uninitializedKeyPair;
    EXPECT_TRUE(isValidKeyPair(uninitializedKeyPair) == "Error: Given Public Key is the Identity element.");

    ECDSAPublicKey publicKey(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                    BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair validKeyPair(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"), publicKey);

    ECC eccObject;
    eccObject.setKeyPair(validKeyPair);

    KeyPair result = eccObject.getKeyPair();

    EXPECT_EQ(validKeyPair.privateKey, result.privateKey);
    EXPECT_EQ(validKeyPair.getPublicKey().x, result.getPublicKey().x);
    EXPECT_EQ(validKeyPair.getPublicKey().y, result.getPublicKey().y);

    ECDSAPublicKey pubKeyIsNotPair(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                          BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair mismatchKeyPair(BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"), pubKeyIsNotPair);

    EXPECT_THROW(eccObject.setKeyPair(mismatchKeyPair), std::invalid_argument);

    EXPECT_TRUE(true);
}

TEST_F(ECC_Test, ExportImportCompressedPublicKey) {
    // Known valid public key
    ECDSAPublicKey originalKey(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                               BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));

    // Export to compressed format
    SecureBytes compressed = originalKey.exportCompressed();

    // Import the compressed key into a new object
    ECDSAPublicKey importedKey(compressed, StandardCurve::secp256k1);

    // Compare x and y of the original and imported key
    Point orig = originalKey.getPublicKey();
    Point imp = importedKey.getPublicKey();

    EXPECT_EQ(orig.x, imp.x);
    EXPECT_EQ(orig.y, imp.y);
}

TEST(ECC_Objects, BigIntInitialization) {
    // Check Hexidecimal value initialization
    BigInt P = "0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577";
    BigInt N = "0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577";
    EXPECT_EQ(P, N);

    // Check decimal value initialization
    BigInt Q = "60903095697897716130768633358908066527972563868462147701232486991401305237654";
    N = "60903095697897716130768633358908066527972563868462147701232486991401305237654";
    EXPECT_EQ(Q, N);

    // Make sure P != Q
    EXPECT_NE(P, Q);

    // Check proper NULL initialization
    BigInt T;
    EXPECT_TRUE(T.isZero());
}

TEST(ECC_Objects, BigIntAssignmentOperator) {
    BigInt P = "0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577";
    BigInt Q = P;
    EXPECT_EQ(P, Q);
}

TEST(ECC_Objects, PointInitialization) {
    // Check Hexidecimal value initialization
    Point P(BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"),
            BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    EXPECT_EQ(P.x, BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"));
    EXPECT_EQ(P.y, BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    // Check decimal value initialization
    Point Q(BigInt("60903095697897716130768633358908066527972563868462147701232486991401305237654"),
            BigInt("34529623772580660154832064486849267429105394335284591488752759902855262151714"));

    EXPECT_EQ(Q.x, BigInt("60903095697897716130768633358908066527972563868462147701232486991401305237654"));
    EXPECT_EQ(Q.y, BigInt("34529623772580660154832064486849267429105394335284591488752759902855262151714"));

    // Make sure P != Q
    EXPECT_NE(P.x, Q.x);
    EXPECT_NE(P.y, Q.y);

    // Check proper NULL initialization
    Point T;
    EXPECT_TRUE(T.x.isZero());
    EXPECT_TRUE(T.y.isZero());
}

TEST(ECC_Objects, PointAssignmentOperator) {
    Point P(BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"),
            BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    Point Q = P;

    EXPECT_EQ(P.x, Q.x);
    EXPECT_EQ(P.y, Q.y);
}

TEST(ECC_Objects, KeyPairInitialization) {
    // Check Hexidecimal value initialization
    ECDSAPublicKey publicKey1(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                    BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair P(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"), publicKey1);

    EXPECT_EQ(P.privateKey, BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"));
    EXPECT_EQ(P.getPublicKey().x, BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"));
    EXPECT_EQ(P.getPublicKey().y, BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));

    // Check decimal value initialization
    ECDSAPublicKey publicKey2(BigInt("41508913618560943505682868066484155222795806420711968987006339848963526306366"),
                    BigInt("47779048823291371033741797327759287667537405354646831765410899091079836405219"));
    KeyPair Q(BigInt("10528738585638442885886470026673783468944086105714080698941011408558582127129"), publicKey2);

    EXPECT_EQ(Q.privateKey, BigInt("10528738585638442885886470026673783468944086105714080698941011408558582127129"));
    EXPECT_EQ(Q.getPublicKey().x, BigInt("41508913618560943505682868066484155222795806420711968987006339848963526306366"));
    EXPECT_EQ(Q.getPublicKey().y, BigInt("47779048823291371033741797327759287667537405354646831765410899091079836405219"));

    // Make sure keyPair1 != keyPair2
    EXPECT_NE(P.getPublicKey().x, Q.getPublicKey().x);
    EXPECT_NE(P.getPublicKey().y, Q.getPublicKey().y);

    // Check proper NULL initialization
    KeyPair T;
    EXPECT_TRUE(T.privateKey.isZero());
    EXPECT_TRUE(T.getPublicKey().x.isZero());
    EXPECT_TRUE(T.getPublicKey().y.isZero());
}

TEST(ECC_Objects, KeyPairAssignmentOperator) {
    ECDSAPublicKey publicKey(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                    BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair P(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"), publicKey);

    KeyPair Q = P;

    EXPECT_EQ(P.privateKey, Q.privateKey);
    EXPECT_EQ(P.getPublicKey().x, Q.getPublicKey().x);
    EXPECT_EQ(P.getPublicKey().y, Q.getPublicKey().y);
}

TEST(ECC_Objects, SignatureInitialization) {
    // Check Hexidecimal value initialization
    Signature P(BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"),
                BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    EXPECT_EQ(P.r, BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"));
    EXPECT_EQ(P.s, BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    // Check decimal value initialization
    Signature Q(BigInt("82423284279682547824030103895721849412830885604189378105816723310541529430329"),
                BigInt("35263610418498196156348668935316331728327496388338009892027000938310937883631"));

    EXPECT_EQ(Q.r, BigInt("82423284279682547824030103895721849412830885604189378105816723310541529430329"));
    EXPECT_EQ(Q.s, BigInt("35263610418498196156348668935316331728327496388338009892027000938310937883631"));

    // Make sure P != Q
    EXPECT_NE(P.r, Q.r);
    EXPECT_NE(P.s, Q.s);

    // Check proper NULL initialization
    Signature T;
    EXPECT_TRUE(T.r.isZero());
    EXPECT_TRUE(T.s.isZero());
}

TEST(ECC_Objects, SignatureAssignmentOperator) {
    Signature P(BigInt("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577"),
                BigInt("0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2"));

    Signature Q = P;

    EXPECT_EQ(P.r, Q.r);
    EXPECT_EQ(P.s, Q.s);
}