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

static BigInt p = "0xecf5aecd1e5515fffacbd75a2816c6ebf49018cdfb4638e185d66a7396b6f8090f8018c7fd95cc34b857dc17f0cc6516bb1346ab4d582cadad7b4103352387b70338d084047c9d9539b6496204b3dd6ea442499207bec01f964287ff6336c3984658336846f56e46861881c10233d2176bf15a5e96ddc780bc868aa77d3ce769";
static BigInt q = "0xbc46c464fc6ac4ca783b0eb08a3c841b772f7e9b2f28babd588ae885e1a0c61e4858a0fb25ac299990f35be85164c259ba1175cdd7192707135184992b6c29b746dd0d2cabe142835f7d148cc161524b4a09946d48b828473f1ce76b6cb6886c345c03e05f41d51b5c3a90a3f24073c7d74a4fe25d9cf21c75960f3fc3863183";
static BigInt d = "0x056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79";

static BigInt n = "0xae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb";
static BigInt e = 65537;

static RSAPrivateKey privateKeyVector = { d, p, q };
static RSAPublicKey publicKeyVector = { n, e };

static const struct RSA_OAEP_TestVectors {
  std::string name;
  RSAPrivateKey privateKey;
  RSAPublicKey publicKey;
  OAEPParams parameters;
  std::string pt;
  std::string ct;
} kRSA_OAEP_TestVectors[] = {
    {
        "OAEP_2048_SHA1",
        privateKeyVector,
        publicKeyVector,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "47e1ab7119fee56c95ee5eaad86f40d0aa63bd33"),
        "8bba6bf82a6c0f86d5f1756e97956870b08953b06b4eb205bc1694ee",
        "53ea5dc08cd260fb3b858567287fa91552c30b2febfba213f0ae87702d068d19bab07fe574523dfb42139d68c3c5afeee0bfe4cb7969cbf382b804d6e61396144e2d0e60741f8993c3014b58b9b1957a8babcd23af854f4c356fb1662aa72bfcc7e586559dc4280d160c126785a723ebeebeff71f11594440aaef87d10793a8774a239d4a04c87fe1467b9daf85208ec6c7255794a96cc29142f9a8bd418e3c1fd67344b0cd0829df3b2bec60253196293c6b34d3f75d32f213dd45c6273d505adf4cced1057cb758fc26aeefa441255ed4e64c199ee075e7f16646182fdb464739b68ab5daff0e63e9552016824f054bf4d3c8c90a97bb6b6553284eb429fcc"
    },
    // Add more test vectors as needed
};

// Define a custom name generator function
inline std::string CustomNameGenerator(const testing::TestParamInfo<RSA_OAEP_TestVectors>& info) {
    const RSA_OAEP_TestVectors& test = info.param;
    return test.name;
}
class RSA_OAEP_Test : public testing::TestWithParam<RSA_OAEP_TestVectors> {};

INSTANTIATE_TEST_SUITE_P(All, RSA_OAEP_Test, testing::ValuesIn(kRSA_OAEP_TestVectors), CustomNameGenerator);