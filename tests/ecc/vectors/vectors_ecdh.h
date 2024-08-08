/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_ecdh.cpp
 *
 */

/* Test vectors from: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Component-Testing */
static const struct ECDHTestVector {
  std::string name;
  StandardCurve curve;
  std::string QCAVSx;
  std::string QCAVSy;
  std::string dIUT;
  std::string QIUTx;
  std::string QIUTy;
  std::string ZIUT;
} kECDHTestVectors[] = {
    {
        "P192",
        StandardCurve::P192,
        "0x42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",
        "0xdfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523",
        "0xf17d3fea367b74d340851ca4270dcb24c271f445bed9d527",
        "0xb15053401f57285637ec324c1cd2139e3a67de3739234b37",
        "0xf269c158637482aad644cd692dd1d3ef2c8a7c49e389f7f6",
        "803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0"
    },
    {
        "P224",
        StandardCurve::P224,
        "0xaf33cd0629bc7e996320a3f40368f74de8704fa37b8fab69abaae280",
        "0x882092ccbba7930f419a8a4f9bb16978bbc3838729992559a6f2e2d7",
        "0x8346a60fc6f293ca5a0d2af68ba71d1dd389e5e40837942df3e43cbd",
        "0x8de2e26adf72c582d6568ef638c4fd59b18da171bdf501f1d929e048",
        "0x4a68a1c2b0fb22930d120555c1ece50ea98dea8407f71be36efac0de",
        "7d96f9a3bd3c05cf5cc37feb8b9d5209d5c2597464dec3e9983743e8"
    },
    {
        "P256",
        StandardCurve::P256,
        "0x700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        "0xdb71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
        "0x7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
        "0xead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
        "0x28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
        "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
    },
    {
        "P384",
        StandardCurve::P384,
        "0xa7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066",
        "0xac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
        "0x3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
        "0x9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f",
        "0xba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
        "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1"
    },
    {
        "P521",
        StandardCurve::P521,
        "0x000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d",
        "0x000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
        "0x0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
        "0x000000602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5",
        "0x000001b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
        "5fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831"
    }
    // Add more test vectors as needed
};

// Define a custom name generator function
std::string CustomNameGenerator(const testing::TestParamInfo<ECDHTestVector>& info) {
    const ECDHTestVector& test = info.param;
    return test.name;
}
class ECDHComputeSharedSecret : public testing::TestWithParam<ECDHTestVector> {
};

INSTANTIATE_TEST_SUITE_P(All, ECDHComputeSharedSecret, testing::ValuesIn(kECDHTestVectors), CustomNameGenerator);