/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_rsa.h
 *
 */

#pragma once

#include "rsa/rsaObjects.h"

BigInt d = "0x90215973f5ff796e33cbd02a6374d982f1cbb2e71acfb39682ddbf20b2dff3e9b9726ec9c8d9e95e4636cdbc4c83fad1670c41894760dab67bc2a27513bfe2f0f414b5c75b827e48333e9ad1371d83e3dda67f73f2d162490aceb88d48135187e9c7977e73a35c8be5cea5e58577e214c1286b6c7af5510bbd3db3ea3f7df85162c3bb41ed833e3e77c986e688546450ecfcb97479a522078e8c381e8e2dfc162af90fbca02d213a36334e7a19b50a10fd01eb99f4cd726d3cd9013da8ed78b5f04f5f54c4b4f9b6f7cf94ce309734c2765542c864c189d44dc09829afad4326c273efc09d089ad2e34a659b02a75256a6105941cdff97086f1626820e025571";
BigInt n = "0xae705ab83435838a1967ff6c9764b1745cb149e3098db7785448f743f6d00727f4689d170a68a45521ff213feff71be3d50fef4f311794ed0dd1c16c8bff9d9815217d5df66bd11d674ae78eb2a40fedda6fa704e152f988de931ec2014ec295b1159c77132c9ebb0de201b3e6c2deb13998e72f2eef4aeb2e53f2e9eb54f9212506e0c3b67d90a2b201dab97fb5370e056fd85afffd38a2493cb0388b10e969b37785300b6c7d355c9697b7be5ff21d5dc9328d5ec792fde8e27abf11754c98fb9761d96145b8752e960b8029ec051c31287ee720b431065416bde1672da27ebac7b73fa820b19384e28426460ae09d7a79dc1e3002218b8c80b4881602ab1b";
BigInt e = 65537;

RSAPrivateKey privateKeyVector = { d };
RSAPublicKey publicKeyVector = { n, e };

std::string pt = "0x102030405060708090a0b0c0d0e0f";
//std::string ptLowerCase = "0x102030405060708090A0B0C0D0E0F";
std::string ct = "0x679fae5f837210cbfb23a79857d9c6bd95f038fe35bbbfba3e26a5f66e22351f3c4a81ccb9e97d974046d246d1b954b2c7fe6455ecd8ad62880b46dc52f9321eac37eea20f91bf4fe7cf6e127f13d81338274d83e4a45f72acd112d76cab9a00416bd64bd5bcc2132a6fe695fe89369d63ddfe0799dab0fdb3bea18cfee6d47198dd5e51f41d40af6f6554a54931203ba2c08510c1da64d58ce0166b142a71e1176e77cd6a78d6c1876f667049f452d5155c7d522df2acf9f347a357b6098a840b21b5653bb72795ece4ad49d51e0c80f511565144f31391f294e0f071a93a6e6d605695304bf15a6d169ba74e73a22bda3933ad0f24d70f2dbf409e9aa9c52d"; 