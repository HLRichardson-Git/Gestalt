/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsaTests.cpp
 */

#include <gestalt/ecdsa.h>
#include <gestalt/sha1.h>

#include "gtest/gtest.h"
#include <string>
#include <iostream>

TEST(TestECDSAkeyGen, testKeyGeneration)
{
    ECDSA key;

    InfInt privatKey = "36911659202040455512047859400253132650624032136469391266733306307680092206180";
    KeyPair keyPair = key.setKeyPair(privatKey);

    KeyPair expected = {{"5844747745739988917638281854633664105197999881451444700670129218777985873582",
                         "108534668176366933332951134464297919708693135604831156472843095507119755132861"},
                         "36911659202040455512047859400253132650624032136469391266733306307680092206180"};

    EXPECT_EQ(keyPair.publicKey.x, expected.publicKey.x);
    EXPECT_EQ(keyPair.publicKey.y, expected.publicKey.y);
    EXPECT_EQ(keyPair.privateKey, expected.privateKey);
}

TEST(TestECDSAsignature, testSigGen)
{
    ECDSA sign;
    
    KeyPair keyPair = {{"5844747745739988917638281854633664105197999881451444700670129218777985873582",
                        "108534668176366933332951134464297919708693135604831156472843095507119755132861"},
                        "36911659202040455512047859400253132650624032136469391266733306307680092206180"};

    std::string message = "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56";

    Signature signature = sign.signMessage(message, keyPair);

    //Signature expected = {"110216805958592777714039232774448176272891959258816807100364142388121497551532",
    //                      "63308726082909978129457058886438288747780283410792251258965605561145777031427"};
    Signature expected = {"33096045414558031720539738434571698304547957960052944906756956543402480052672",
                          "49144826773163876108584619613203665196553048128653206388567733462234753034033"};

    EXPECT_EQ(signature.r, expected.r);
    EXPECT_EQ(signature.s, expected.s);
}

TEST(TestECDSAsignature, testSigVer)
{
    ECDSA sign;
    
    Point publicKey = {"5844747745739988917638281854633664105197999881451444700670129218777985873582",
                       "108534668176366933332951134464297919708693135604831156472843095507119755132861"};

    std::string message = "2f4a1d40e934b0c88b919eeb559f3a03ff65226b22064b6f3666608f28ad9db9";

    Signature signature = {"33096045414558031720539738434571698304547957960052944906756956543402480052672",
                           "107136589985951679660690720598415431026235126579522817745475725016806906002371"};

    bool verify = sign.verifySignature(message, signature, publicKey);

    EXPECT_EQ(verify, 1);
}

/*
TEST(TestECDSAsignature, testInducedFailureVerification)
{
    ECDSA sign;
    KeyPair keyPair = sign.generateKeyPair();

    std::string message = "1AC5";

    Signature signature = sign.signMessage(message, keyPair);

    message= "1AC5FFF";
    bool verify = sign.verifySignature(message, signature, keyPair.publicKey);

    EXPECT_EQ(verify, 0);
}*/