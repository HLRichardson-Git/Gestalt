/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_hmac.h
 *
 * This file contains the test vectors to be used in ../hmacTests.cpp unit tests
 */

#pragma once

#include "gtest/gtest.h"

struct HMAC_TestVectors {
    std::string name;
    std::string key;
    std::string data;
    std::string expected;
};

const struct HMAC_TestVectors HMAC_SHA1_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "4fd0b215276ef12f2b3e4c8ecac2811498b656fc"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "e977b6b86e9f1920f01be85e9cea1f5a15b89421"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "ced90feb938a8e156e1e643238d446de00439007"
    }
};

const struct HMAC_TestVectors HMAC_SHA224_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "f524670b7e34f31467de0aa96593861cf65117d414fb2d86158d760e"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "b27b6be7aae40898ce6b6b58e5ed5f505456515acb97a581500c07bc"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "1f70dd7fa76562b63d19b76b8b0d4443ac45e39b47f116a3d2b43e4c"
    }
};

const struct HMAC_TestVectors HMAC_SHA256_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "29dc3b24e96ab703b3cdad77288ad2d7e4c9129ab46558afe24e23431e436108"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "4344f4d674c7854db70fc3c91f726eb2ef99e7f115fa4156c4efe59268f76cf8"
    }
};

const struct HMAC_TestVectors HMAC_SHA384_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "30ddb9c8f347cffbfb44e519d814f074cf4047a55d6f563324f1c6a33920e5edfb2a34bac60bdc96cd33a95623d7d638"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "58f184a9634abf60a89b822c6a1b0aa9653a309615fc4667e512bbeb9a74a12fca7ccde35bcf7b166e9f4942884a2350"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "b38e1b7fc7ae7af34e8e24fca3dd6b5c67ffdee95a53aeeaccb61ac90f87ed8893c9a6990927097019243ba4504a9b63"
    }
};

const struct HMAC_TestVectors HMAC_SHA512_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "3926a207c8c42b0c41792cbd3e1a1aaaf5f7a25704f62dfc939c4987dd7ce060009c5bb1c2447355b3216f10b537e9afa7b64a4e5391b0d631172d07939e087a"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "d75a832599900737e1b1ac33a50c2451f00de527256892d451e3e40bab342690a5ae84ba4dc75afaac784e747531627e131dcf83a52f3125885c2f844951eb4d"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "dd24d0f759d2f887f5ce52f94a6a0497b29af45703899f5a54605996d0fe032c3b59c86e21f29c9824e9290f7e6e9ea5d11e6806fae453bb88f8656171647d3c"
    }
};

const struct HMAC_TestVectors HMAC_SHA512_224_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "de43f6b96f2d08cebe1ee9c02c53d96b68c1e55b6c15d6843b410d4c"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "28bc0433ef684ea9877c2f2437aa0ccfc2e8eb3a9b4c731606877b4f"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "d4e5f3635a000d4985a50c86ea868b0ac149bc937752272d19e722da"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "d6031647611fa39e08bce2f1118e60c7ae0ff75fd0cf338cea5afacd"
    }
};

const struct HMAC_TestVectors HMAC_SHA512_256_VECTORS[] = {
    {
     "nullKeyedHash", 
     "",
     "",
     "b79c9951df595274582dc094a1ba46c33e4a36878b2d83cb8553f0fe467dcdcf"
    },
    {
     "shortKeyedHash",
     "key", 
     "abc",
     "f367b7ca80ab2cf85c23e58b73a8fd525a6fa2c66ff105804a2d4cf4df06e129"
    },
    {
     "mediumKeyedHash", 
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "8ac7211e6947a4804d6a1a729207e05a1c61981c8f48518cf8585504be9bc274"
    },
    {
     "longKeyedHash",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "c64be39473e1b8d89e82999495f7c79cf0a5b44c30542f385c3649c811a5d8d6"
    }
};

std::string CustomNameGenerator(const testing::TestParamInfo<HMAC_TestVectors>& info) {
    const HMAC_TestVectors& test = info.param;
    return test.name;
}

class HMAC_SHA1 : public testing::TestWithParam<HMAC_TestVectors> {};
class HMAC_SHA2_224 : public testing::TestWithParam<HMAC_TestVectors> {};
class HMAC_SHA2_256 : public testing::TestWithParam<HMAC_TestVectors> {};
class HMAC_SHA2_384 : public testing::TestWithParam<HMAC_TestVectors> {};
class HMAC_SHA2_512 : public testing::TestWithParam<HMAC_TestVectors> {};
class HMAC_SHA2_512_224 : public testing::TestWithParam<HMAC_TestVectors> {};
class HMAC_SHA2_512_256 : public testing::TestWithParam<HMAC_TestVectors> {};

INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA1, testing::ValuesIn(HMAC_SHA1_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA2_224, testing::ValuesIn(HMAC_SHA224_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA2_256, testing::ValuesIn(HMAC_SHA256_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA2_384, testing::ValuesIn(HMAC_SHA384_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA2_512, testing::ValuesIn(HMAC_SHA512_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA2_512_224, testing::ValuesIn(HMAC_SHA512_224_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, HMAC_SHA2_512_256, testing::ValuesIn(HMAC_SHA512_256_VECTORS), CustomNameGenerator);