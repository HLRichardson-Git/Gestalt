/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsaTests.cpp
 */

#include <gestalt/ecdsa.h>

#include "gtest/gtest.h"
#include <string>
#include <iostream>

TEST(TestECDSAkeyGen, keyGen)
{
    ECDSA ecdsa;

    InfInt privatKey = "36911659202040455512047859400253132650624032136469391266733306307680092206180";
    KeyPair keyPair = ecdsa.setKeyPair(privatKey);

    KeyPair expected = {{"5844747745739988917638281854633664105197999881451444700670129218777985873582",
                         "108534668176366933332951134464297919708693135604831156472843095507119755132861"},
                         "36911659202040455512047859400253132650624032136469391266733306307680092206180"};

    EXPECT_EQ(keyPair.publicKey.x, expected.publicKey.x);
    EXPECT_EQ(keyPair.publicKey.y, expected.publicKey.y);
    EXPECT_EQ(keyPair.privateKey, expected.privateKey);
}

TEST(TestECDSAsignature, sigGen)
{
    ECDSA ecdsa;
    
    KeyPair keyPair = {{"5844747745739988917638281854633664105197999881451444700670129218777985873582",
                        "108534668176366933332951134464297919708693135604831156472843095507119755132861"},
                        "36911659202040455512047859400253132650624032136469391266733306307680092206180"};

    const InfInt k = "67228059374187986264907871817984995299114694677537144137068659840319595636958";
    std::string message = "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a";

    Signature signature = ecdsa.signMessage(message, keyPair, k);

    Signature expected = {"47760720287736789683069083573948166072371263571273732180050208132677181355037",
                          "42326741621592248130836344113577397674154087107773159600666149373314130004215"};

    EXPECT_EQ(signature.r, expected.r);
    EXPECT_EQ(signature.s, expected.s);
}

TEST(TestECDSAsignature, sigVer)
{
    ECDSA ecdsa;
    
    Point publicKey = {"5844747745739988917638281854633664105197999881451444700670129218777985873582",
                       "108534668176366933332951134464297919708693135604831156472843095507119755132861"};

    std::string message = "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a";

    Signature signature = {"47760720287736789683069083573948166072371263571273732180050208132677181355037",
                           "42326741621592248130836344113577397674154087107773159600666149373314130004215"};

    bool verify = ecdsa.verifySignature(message, signature, publicKey);

    EXPECT_EQ(verify, true);
}

TEST(TestECDSAsignature, testSignatureRoundTrip_WithP256) {
    ECDSA ecdsa(StandardCurve::P256);
    
    KeyPair keyPair = {{"13025038577035367868028521755794722443625521375819261296867266283988044595075",
                        "93289668407624934715496999573355830041670389702655399598324526119224759438505"},
                        "36911659202040455512047859400253132650624032136469391266733306307680092206180"};

    const InfInt k = "67228059374187986264907871817984995299114694677537144137068659840319595636958";
    
    std::string message = "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56";

    Signature signature = ecdsa.signMessage(message, keyPair, k);

    Signature expected = {"110216805958592777714039232774448176272891959258816807100364142388121497551532",
                          "63308726082909978129457058886438288747780283410792251258965605561145777031427"};

    EXPECT_EQ(signature.r, expected.r);
    EXPECT_EQ(signature.s, expected.s);

    bool verify = ecdsa.verifySignature(message, signature, keyPair.publicKey);

    EXPECT_EQ(verify, true);
}

TEST(TestECDSAsignature, testInducedFailureVerification)
{
    ECDSA ecdsa;
    KeyPair keyPair = ecdsa.generateKeyPair();

    std::string message = "1AC5";

    Signature signature = ecdsa.signMessage(message, keyPair);

    message= "1AC6";
    bool verify = ecdsa.verifySignature(message, signature, keyPair.publicKey);

    EXPECT_EQ(verify, false);
}