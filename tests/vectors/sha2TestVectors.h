/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2TestVecors.h
 *
 * This file contains the test vectors to be used in ../sha2Tests.cpp unit tests
 */

#pragma once

#include "gtest/gtest.h"

struct SHA2TestVectors {
    std::string name;
    size_t repetitions;
    std::string in;
    std::string expected;
};

const struct SHA2TestVectors SHA224_VECTORS[] = {
    {
     "nullHash", 
     1,
     "",
     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    },
    {
     "shortHash",
     1, 
     "abc",
     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    },
    {
     "mediumHash", 
     1,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    },
    {
     "longHash",
     1, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
    },
    {
     "largeHash",
     1000000, 
     "a",
     "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
    },
    {
     "extremelyLargeHash",
     16777216, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
     "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"
    }
};

const struct SHA2TestVectors SHA256_VECTORS[] = {
    {
     "nullHash", 
     1,
     "",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
     "shortHash", 
     1,
     "abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
     "mediumHash", 
     1,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    },
    {
     "longHash", 
     1,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    },
    {
     "largeHash",
     1000000, 
     "a",
     "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    },
    {
     "extremelyLargeHash",
     16777216, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
     "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
    }
};

const struct SHA2TestVectors SHA384_VECTORS[] = {
    {
     "nullHash", 
     1,
     "",
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    },
    {
     "shortHash", 
     1,
     "abc",
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    },
    {
     "mediumHash", 
     1,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
    },
    {
     "longHash", 
     1,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
    },
    {
     "largeHash",
     1000000, 
     "a",
     "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
    },
    {
     "extremelyLargeHash",
     16777216, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
     "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"
    }
};

const struct SHA2TestVectors SHA512_VECTORS[] = {
    {
     "nullHash", 
     1,
     "",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    },
    {
     "shortHash", 
     1,
     "abc",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    },
    {
     "mediumHash", 
     1,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    },
    {
     "longHash", 
     1,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    },
    {
     "largeHash",
     1000000, 
     "a",
     "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    },
    {
     "extremelyLargeHash",
     16777216, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
     "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
    }
};

const struct SHA2TestVectors SHA512_224_VECTORS[] = {
    {
     "nullHash", 
     1,
     "",
     "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
    },
    {
     "shortHash", 
     1,
     "abc",
     "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    },
    {
     "mediumHash", 
     1,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174"
    },
    {
     "longHash", 
     1,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
    },
    {
     "largeHash",
     1000000, 
     "a",
     "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287"
    },
    {
     "extremelyLargeHash",
     16777216, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
     "9a7f86727c3be1403d6702617646b15589b8c5a92c70f1703cd25b52"
    }
};

const struct SHA2TestVectors SHA512_256_VECTORS[] = {
    {
     "nullHash", 
     1,
     "",
     "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    },
    {
     "shortHash", 
     1,
     "abc",
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    },
    {
     "mediumHash", 
     1,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"
    },
    {
     "longHash", 
     1,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
    },
    {
     "largeHash",
     1000000, 
     "a",
     "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21"
    },
    {
     "extremelyLargeHash",
     16777216, 
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
     "b5855a6179802ce567cbf43888284c6ac7c3f6c48b08c5bc1e8ad75d12782c9e"
    }
};

// Define a custom name generator function
std::string CustomNameGenerator(const testing::TestParamInfo<SHA2TestVectors>& info) {
    const SHA2TestVectors& test = info.param;
    return test.name;
}
class SHA224HashTest : public testing::TestWithParam<SHA2TestVectors> {};
class SHA256HashTest : public testing::TestWithParam<SHA2TestVectors> {};
class SHA3844HashTest : public testing::TestWithParam<SHA2TestVectors> {};
class SHA512HashTest : public testing::TestWithParam<SHA2TestVectors> {};
class SHA512_224HashTest : public testing::TestWithParam<SHA2TestVectors> {};
class SHA512_256HashTest : public testing::TestWithParam<SHA2TestVectors> {};

INSTANTIATE_TEST_SUITE_P(All, SHA224HashTest, testing::ValuesIn(SHA224_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, SHA256HashTest, testing::ValuesIn(SHA256_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, SHA3844HashTest, testing::ValuesIn(SHA384_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, SHA512HashTest, testing::ValuesIn(SHA512_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, SHA512_224HashTest, testing::ValuesIn(SHA512_224_VECTORS), CustomNameGenerator);
INSTANTIATE_TEST_SUITE_P(All, SHA512_256HashTest, testing::ValuesIn(SHA512_256_VECTORS), CustomNameGenerator);