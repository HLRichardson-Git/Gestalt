/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsaTests.cpp
 *
 * This file containts the unit tests for the ECDSA (Elliptic Curve Digital Signature Algorithm) Gestalt 
 * implementation. These tests cover various scenarios including keyGen, sigGen, sigVer, pair-wise consistency test,
 * and an induced failure test. For sigGen and sigVer we test all added standard curves with a sha-256 hash.
 * 
 */

#include <gestalt/ecdsa.h>

#include "gtest/gtest.h"
#include <vector>

TEST(TestECDSAkeyGen, keyGen)
{
    ECDSA ecdsa;

    std::string privateKey = "0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464";

    ecdsa.setKeyPair(privateKey);
    KeyPair resultKeyPair = ecdsa.getKeyPair();

    Point publicKey("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
                    "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");
    KeyPair expected("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464", publicKey);

    EXPECT_TRUE(mpz_cmp(resultKeyPair.privateKey, expected.privateKey) == 0);
    EXPECT_TRUE(mpz_cmp(resultKeyPair.publicKey.x, expected.publicKey.x) == 0);
    EXPECT_TRUE(mpz_cmp(resultKeyPair.publicKey.y, expected.publicKey.y) == 0);
}

/* Test vectors from: https://www.rfc-editor.org/rfc/rfc6979 */
static const struct ECDSATestVector {
  std::string name;
  StandardCurve curve;
  std::string msg;
  std::string privateKey;
  std::string k;
  std::string expected_r;
  std::string expected_s;
} kECDSATestVectors[] = {
    {
        "P192_SHA256",
        StandardCurve::P192,
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
        "0x32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496",
        "0x4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55",
        "0xCCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85"
    },
    {
        "P224_SHA256",
        StandardCurve::P224,
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "0xF220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
        "0xAD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC",
        "0x61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA",
        "0xBC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101"
    },
    {
        "P256_SHA256",
        StandardCurve::P256,
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
        "0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
    },
    {
        "P384_SHA256",
        StandardCurve::P384,
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "0x6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
        "0x180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C899F9F2EDF9747A9B60",
        "0x21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
        "0xF3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0"
    },
    {
        "P521_SHA256",
        StandardCurve::P521,
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
        "0x0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0",
        "0x1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
        "0x04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC"
    },
    {
        "secp256k1_SHA256",
        StandardCurve::secp256k1,
        "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a",
        "0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464",
        "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE",
        "0x69979C16867D369D95E8852B4C68B323A66A7AAE0A3C112B2F426726EF93B41D",
        "0x5D9416379D19A392740CF6EE448161D630E04CD968EC74DB3EA4C6CE67CC48F7"
    },
    // Add more test vectors as needed
};

// Define a custom name generator function
std::string CustomNameGenerator(const testing::TestParamInfo<ECDSATestVector>& info) {
    const ECDSATestVector& test = info.param;
    return test.name;
}
class ECDSASignatureGenTest : public testing::TestWithParam<ECDSATestVector> {
};

INSTANTIATE_TEST_SUITE_P(All, ECDSASignatureGenTest, testing::ValuesIn(kECDSATestVectors), CustomNameGenerator);

TEST_P(ECDSASignatureGenTest, sigGen)
{
    const ECDSATestVector &test = GetParam();
    SCOPED_TRACE(test.name);

    ECDSA ecdsa(test.curve, test.privateKey);
    
    BigInt k_value(test.k);

    Signature signature = ecdsa.signMessage(test.msg, k_value);

    Signature expected(test.expected_r, test.expected_s);

    EXPECT_TRUE(mpz_cmp(signature.r, expected.r) == 0);
    EXPECT_TRUE(mpz_cmp(signature.s, expected.s) == 0);
}

class ECDSASignatureVerTest : public testing::TestWithParam<ECDSATestVector> {};

INSTANTIATE_TEST_SUITE_P(All, ECDSASignatureVerTest, testing::ValuesIn(kECDSATestVectors), CustomNameGenerator);

TEST_P(ECDSASignatureVerTest, sigVer)
{
    const ECDSATestVector &test = GetParam();
    SCOPED_TRACE(test.name);
    
    ECDSA ecdsa(test.curve, test.privateKey);

    Signature signature(test.expected_r, test.expected_s); 

    bool verify = ecdsa.verifySignature(test.msg, signature);

    EXPECT_TRUE(verify);
}

TEST(TestECDSAsignature, PWCT) 
{
    ECDSA ecdsa(StandardCurve::P256, "0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");

    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    std::string digest = "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56";

    Signature signature = ecdsa.signMessage(digest, k);

    Signature expected("0xF3AC8061B514795B8843E3D6629527ED2AFD6B1F6A555A7ACABB5E6F79C8C2AC", 
                       "0x8BF77819CA05A6B2786C76262BF7371CEF97B218E96F175A3CCDDA2ACC058903");

    EXPECT_TRUE(mpz_cmp(signature.r, expected.r) == 0);
    EXPECT_TRUE(mpz_cmp(signature.s, expected.s) == 0);

    bool verify = ecdsa.verifySignature(digest, signature);

    EXPECT_TRUE(verify);
}

TEST(TestECDSAsignature, inducedFailureVerification)
{
    ECDSA ecdsa;

    std::string digest = "1AC5";

    Signature signature = ecdsa.signMessage(digest);

    digest= "1AC6";
    bool verify = ecdsa.verifySignature(digest, signature);

    EXPECT_TRUE(!verify);
}

class TestECDSA : public ::testing::Test {
private:
    ECDSA ecdsa;
protected:
    void prepareMessage(const std::string& messageHash, mpz_t& result) { 
        ecdsa.prepareMessage(messageHash, result);
    };
    bool isInvalidSignature(Signature S) { return ecdsa.isInvalidSignature(S); };
    void setKeyPair(const std::string& givenKey) { ecdsa.setKeyPair(givenKey); };
    Signature generateSignature(const mpz_t& e, mpz_t& k) { return ecdsa.generateSignature(e, k); };
};

TEST_F(TestECDSA, PrepareMessage)
{
    BigInt result;
    BigInt expected;

    std::string smallerThanBitSize = "0xFFF";
    expected = "0xFFF";
    prepareMessage(smallerThanBitSize, result.n);
    EXPECT_TRUE(mpz_cmp(result.n, expected.n) == 0);

    std::string sameBitSize = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    expected = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    prepareMessage(sameBitSize, result.n);
    EXPECT_TRUE(mpz_cmp(result.n, expected.n) == 0);

    std::string largerThanBitSize = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    expected = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    prepareMessage(largerThanBitSize, result.n);
    EXPECT_TRUE(mpz_cmp(result.n, expected.n) == 0);
}

TEST_F(TestECDSA, IsValidSignature) 
{
    Signature validSig("0xF3AC8061B514795B8843E3D6629527ED2AFD6B1F6A555A7ACABB5E6F79C8C2AC", 
                       "0x8BF77819CA05A6B2786C76262BF7371CEF97B218E96F175A3CCDDA2ACC058903");
    Signature invalidSig;
    
    EXPECT_FALSE(isInvalidSignature(validSig));
    EXPECT_TRUE(isInvalidSignature(invalidSig));
}

TEST_F(TestECDSA, GenerateSignature) 
{
    std::string digest = "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a";
    BigInt e;
    prepareMessage(digest, e.n);
    setKeyPair("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");
    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    Signature signature = generateSignature(e.n, k.n);

    Signature expected("0x69979C16867D369D95E8852B4C68B323A66A7AAE0A3C112B2F426726EF93B41D",
                       "0x5D9416379D19A392740CF6EE448161D630E04CD968EC74DB3EA4C6CE67CC48F7");

    EXPECT_TRUE(mpz_cmp(signature.r, expected.r) == 0);
    EXPECT_TRUE(mpz_cmp(signature.s, expected.s) == 0);
}