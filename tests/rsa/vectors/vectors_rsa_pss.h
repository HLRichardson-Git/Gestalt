/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_rsa_oaep.h
 *
 */

#pragma once

#include <gestalt/rsa.h>
#include "rsa/rsaObjects.h"

/*
 * Test Vector sources:
 *  [1] https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/oaep-vect.txt
 *  [2] https://boringssl.googlesource.com/boringssl/+/refs/heads/master/third_party/wycheproof_testvectors
 *
*/

static BigInt p = "0xd17f655bf27c8b16d35462c905cc04a26f37e2a67fa9c0ce0dced472394a0df743fe7f929e378efdb368eddff453cf007af6d948e0ade757371f8a711e278f6b";
static BigInt q = "0xc6d92b6fee7414d1358ce1546fb62987530b90bd15e0f14963a5e2635adb69347ec0c01b2ab1763fd8ac1a592fb22757463a982425bb97a3a437c5bf86d03f2f";
static BigInt d = "0x050e2c3e38d886110288dfc68a9533e7e12e27d2aa56d2cdb3fb6efa990bcff29e1d2987fb711962860e7391b1ce01ebadb9e812d2fbdfaf25df4ae26110a6d7a26f0b810f54875e17dd5c9fb6d641761245b81e79f8c88f0e55a6dcd5f133abd35f8f4ec80adf1bf86277a582894cb6ebcd2162f1c7534f1f4947b129151b71";

static BigInt n = "0xa2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe888b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de7751222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5";
static BigInt e = 65537;

static RSAPrivateKey privateKeyVector = { d, p, q };
static RSAPublicKey publicKeyVector = { n, e };

static const struct RSA_PSS_TestVectors {
  std::string name;
  RSA_SECURITY_STRENGTH keySecurityStrength;
  RSAPrivateKey privateKey;
  RSAPublicKey publicKey;
  PSSParams parameters;
  std::string pt;
  std::string ct;
} kRSA_PSS_TestVectors[] = {
    {   // Source [1]
        "PSS_1024_SHA1",
        RSA_SECURITY_STRENGTH::RSA_1024,
        privateKeyVector,
        publicKeyVector,
        PSSParams(RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, 20, "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"),
        "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc",
        "8daa627d3de7595d63056c7ec659e54406f10610128baae821c8b2a0f3936d54dc3bdce46689f6b7951bb18e840542769718d5715d210d85efbb596192032c42be4c29972c856275eb6d5a45f05f51876fc6743deddd28caec9bb30ea99e02c3488269604fe497f74ccd7c7fca1671897123cbd30def5d54a2b5536ad90a747e"
    }
};

// Define a custom name generator function
inline std::string CustomNameGenerator(const testing::TestParamInfo<RSA_PSS_TestVectors>& info) {
    const RSA_PSS_TestVectors& test = info.param;
    return test.name;
}
class RSA_PSS_Test : public testing::TestWithParam<RSA_PSS_TestVectors> {};

INSTANTIATE_TEST_SUITE_P(RSA_Padding_Signature, RSA_PSS_Test, testing::ValuesIn(kRSA_PSS_TestVectors), CustomNameGenerator);