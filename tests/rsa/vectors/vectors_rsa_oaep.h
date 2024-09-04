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

static BigInt p = "0xbf7be0c5d1e70811470fbd96f922989f783d5f12714971c5a3e70e093de76bd1f52618572e83951cdb4f7d30dec892c5aaf8112081455f7047a1fa6599c507b1cbaf6b4be223a60dfe26e80f0b4baf6cc98d04420c18cab902e248a64aa38c9ffba7dd3e1fbae71151283681e5e1058ee5c9ab476a016083f04fe0afe2736527";
static BigInt q = "0xc56538b3e9f3f9939aba958962d632ff86e87d43d7ffdf2073d6db61886e0f6c8abd60807022398b053ecdb7d142416a7922b576f91e4d995b762f37cd6a07affb290b6879ee045b978c9fafa81c8227effdfad787e5f53b46f2d3660d9386a491b5e4b80b5617adfaadb28f95917bac51727d51fda3994392ab95051345010d";
static BigInt d = "0x92efca032ba58fb5da7d93fed4c0430d8fbbe0d4766e4ec57a15a44f75c8450eba870507cecf34e740429321c39cf9eb4c0dec690a2062342a6c3dcd3d17eca2cfed0d639208495e5ee03918bd084f147986ce7d99131a76c9c0f33db6ef76064131bfa8b79b1eb97fb9e00a9a865382bc7e0b0f1c1b1138a692c3d4532778c8bda41a652a50a5677bf46873d1c28c5e5c076eada0cdd16c714664c269d3bc71ff7137c38f27719bc99680af6757b787ee63eaa109d0c9d36581fc977d694b88451e06c681d05c007dd6ab397c79acca0c94fa1ce6170d179557705ce4ba8009713cf9de90ead70ae8fa3010d8b1b95f3abb66e6c8ede5ee4b0881465a3db8e9";

static BigInt n = "0x93a60a41945a4670161ea632e9644630301499e9b9da7501c204da5dcb8122bcbdd3529571b9f38519f0be9ee4419a41140ce453e9ca180014b9e8fb27ef4d2eb5089eec2c0606d10b77b443c58516dfee254fedc11d529e8d4f9df607e8e88bdb4edae1cb18bdc6213e4766557c1dc1ad510a44c9ce7e6943513f6012322fb269f7d47b1b41341d1d172f1b43ea903cd5c2ba102c7f56995e083ce8506482018dc8c9364a0db847934177a6a5cf5be2c2cfe87d246dbb0d10a5586f7db18ae14d6956dcb64f9266e43a50a81243122acb9234aa5d5a76fd2428c6b3a92f1937d0f85c4d9f769fc22a62d9886688572a68a89aabf44cbb0e86535f301bc449fb";
static BigInt e = 65537;

static RSAPrivateKey privateKeyVector = { d, p, q };
static RSAPublicKey publicKeyVector = { n, e };

// Source [1]
static BigInt p1 = "0xd32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d";
static BigInt q1 = "0xcc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77";
static BigInt d1 = "0x53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1";

static BigInt n1 = "0xa8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb";
static BigInt e1 = 65537;

static RSAPrivateKey privateKeyVector1 = { d1, p1, q1 };
static RSAPublicKey publicKeyVector1 = { n1, e1 };

// Source [1]
static BigInt p2 = "0xecf5aecd1e5515fffacbd75a2816c6ebf49018cdfb4638e185d66a7396b6f8090f8018c7fd95cc34b857dc17f0cc6516bb1346ab4d582cadad7b4103352387b70338d084047c9d9539b6496204b3dd6ea442499207bec01f964287ff6336c3984658336846f56e46861881c10233d2176bf15a5e96ddc780bc868aa77d3ce769";
static BigInt q2 = "0xbc46c464fc6ac4ca783b0eb08a3c841b772f7e9b2f28babd588ae885e1a0c61e4858a0fb25ac299990f35be85164c259ba1175cdd7192707135184992b6c29b746dd0d2cabe142835f7d148cc161524b4a09946d48b828473f1ce76b6cb6886c345c03e05f41d51b5c3a90a3f24073c7d74a4fe25d9cf21c75960f3fc3863183";
static BigInt d2 = "0x056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79";

static BigInt n2 = "0xae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb";
static BigInt e2 = 65537;

static RSAPrivateKey privateKeyVector2 = { d2, p2, q2 };
static RSAPublicKey publicKeyVector2 = { n2, e2 };

// Source [2]
static RSAPrivateKey privateKeyVector3 = { "0x56d0756ceddf7b1e5b258f783b99e036e25675eca054ae9b6ed7552776c69b2728f76e08973556b0a35ddbade9d462ed12bfc46fd254a07ef4ee043ab24d1ef00f8d214cd1d906911e92c4a212d9a981da74b8d18208153d583035d6642b87a23371787867efd02c336eab01486266c853a052490deaea430c6043a6b240b6e9d71e16f29255f2ceeb35d1a4ae25ae0dc9a436fb5dc30381cce982acc824961976df683173a02a540c403f3c8560243ceb5b798abcdc20f3c85d9532b0f0b0826f1b6352c5adac757fe3224b822455cc529fcdc8a220b0469f321f56bd1853d8a70b893f404cc06317e084173770c7d4c836281ac251353fcee4ac393838a1a1" };
static RSAPublicKey publicKeyVector3 = { "0x00c32cd0e1441fde8a2896ca3a133735be2d1010777cfc739afc77b6daa66f367d4876dccb3021fc22c25450a68d6cfb1191d485cbfba5ec45b49286d7cae2bdae553f47e10b94f867abcc6d0affc733bacc725e5ab4de1aba19a39d748b4c1355d5a6a710a52bd04c0c24e7bc3bdab8f3ce3ae86ecb31c4b45e10b40ddb5fdd40cb2411bcf5b1d392e1eef959cff2709a6e02b20ff3b4343641a6b78599586edc9b673d9f3f5e9d339ceebf96a1a31655876c39fcb00b1c3e571908c9b744765047abb5c23ecc42e551e13755e38cc9a13e1e02bcd5dcec9c301fab75be3e1a8ee9c42981607aba7855f4bbe76c8c160e80468b54bdf9f438b177c33dee30b0f5",
                                          65537 }; 

// Source [2]
static RSAPrivateKey privateKeyVector4 = { "0x7627eef3567b2a27268e52053ecd31c3a7172ccb9ddcee819b306a5b3c66b7573ca4fa88efc6f3c4a00bfa0ae7139f64543a4dac3d05823f6ff477cfcec84fe2ac7a68b17204b390232e110310c4e899c4e7c10967db4acde042dbbf19dbe00b4b4741de1020aaaaffb5054c797c9f136f7d93ac3fc8caff6654242d7821ebee517bf537f44366a0fdd45ae05b9909c2e6cc1ed9281eff4399f76c96b96233ec29ae0bbf0d752b234fc197389f51050aa1acd01c074c3ac8fbdb9ea8b651a95995e8db4ad5c43b6c8673e5a126e7ee94b8dff4c5afc01259bc8da76950bae6f8bae715f50985b0d6f66d04c6fef3b700720eecdcdf171bb7b1ecbe7289c467c1" };
static RSAPublicKey publicKeyVector4 = { "0x00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5",
                                          65537 };  

// Source [2]
static RSAPrivateKey privateKeyVector5 = { "0x72ac6bb6d9a5726e454b5430c71125c6e9ad5fd42e1c5a18a8343e9d83d72214386b2308c0b8ec5ec6759dcfcd6a21f88b8ceaf46403923eb86ac3d14a8592e95de0462e14085c3f17db005dc4fac87b4a2d1ede5cf851d5745c8651a4438c0a4d746ad72e419207964728c301bf379a01c094e9693376f721137d3dc76ee47c9790fbd590b7d6a8d626e21b277ef17a4e4f7e0171c1146e1ec324fa97f30d3a1bae08f8d5f6e92cfc121665239c429167359e9650434b29d2015190356adfee12f25b341b08f12b7fec6379598af7d5cc24fe7f00de1d47133ce3ad8b6be1c9a854e33fb952e164ac6dd2a9052186ee144ee7dd986a8f03891d0da21ed78516dcdc2ac89cdddc8b544731d66f9d89bf17a50c6d987a598b02c938dc36521b881ea994e4c8fb2ba8fd001f73335d4dd1bdbe177d3093cf3883657c9ff944e8f5c9cde548b7c1b0741929b0d74977ecda694d940aefd9d2fc75323e0b3a114b99feaf3e2518f5158d1fd9d953aa20af158e67d27e2ce2f18d97fd02f369981979" };
static RSAPublicKey publicKeyVector5 = { "0x00c6fe23792566023c265287c5ac6f71541c0994d11d059ee6403986efa21c24b51bd91d8862f9df79a4e328e3e27c83df260b25a9b43420affc44b51e8d7525b6f29c372a405104732007527a62ed82fac73f4892a80e09682a41a58cd347017f3be7d801334f92d9321aafd53b51bffabfc752cfccae0b1ee03bdaff9e428cc1c117f1ac96b4fe23f8c23e6381186a66fd59289339ae55c4bcdadbff84abdaa532240d4e1d28b2d0481dadd3b246557ca8fe18092817730b39e6ee378ffcc85b19ffdc916a9b991a6b66d4a9c7bab5f5e7a3722101142e7a4108c15d573b15289e07e46eaea07b42c2abcba330e99554b4656165bb4c0db2b6393a07eca575c51a93c4e15bdb0f747909447e3efe34c67ca8954b530e56a20a1b6d84d45ed1bcd3aa58ec06f184ee5857aaa819e1cca9a26f4e28d6b977d33916db9896d252d1afa762e287cb0d384cc75bfe53f4e922d02dd0a481c042e2d306b4b3c189371e575b25e0005a164cf69dd0976e4d5be476806ea6be6084e71ab4f5ac5c1b1203",
                                          65537 };

// Source [2]
static RSAPrivateKey privateKeyVector6 = { "0x5a3dc962dafca26cb3640e73bea7439a9f1874bc23e04226ccd89e7ba5c3b938a1a293b70dbab0f9f0f57f66951447dc33e730fd7e2c2a164d47ac502b07dd24cd3c142c2a79e4ceab5cfabff4478754b25a8c02c1a47d80d9f37abe442ca9a78b23f631b6ff3e15a4956d7f18590cdeb206d5e2b698bd084f260e82ef28ff9ec6dbc85a895ec8a3865750f501b96125db1bbdd99a4ae4688adb304aabdfc4e0cfb9fe6b6bc0db74c88af8217eed738a0d04fe8d32c1d110370ce1c1b2f630657350694942730878e6fff77ada7e9a317df8bc059ea7081325306b8eb2fa0d3a3d89fae476d9344892bcd5a42cf83b7bcf3e0e51b4c78e72b3207a60a701adb1" };
static RSAPublicKey publicKeyVector6 = { "0x00cda6fa5ca76bfe0492ec57e0a3bfff7272dc8d1e25ad1fb338aa050f02c104e63133d6b5b7c4985ebbae9ac036a5b9c03074d60aec8e25baf392a0c430ff05b88e948805d3dd74511d8885250a7b574215ada015c559076686e253ccc96c0815b1291ee787cc3363b4f77d930eb998d7c582b24cea9ce21de9722791989863a27ebc80a00de5bd2f9228775e5a4ceb054d58c9be36a054336971a13642dd9510dd696aa268db3aab2299d5d88f8e562434d1427094d3df8e72d1ef69b4ed34d12bac375223b2a25cf227f735f816e85e17239304769a6082154cd15899fc1eaefb69b748a3e5ed24d38372597de3e4e2a27b951d6ac7db182d6809d8ff511b7f",
                                          65537 };

// Source [2]
static RSAPrivateKey privateKeyVector7 = { "0x0a5c2790a591c3ecf4f6281c17e1038845e540a95f21294a7ceecd75b18c54c50c02e789311c1b0091526f87ab3cc8d48188e980ce0e0377bec00e9f7d9793583cb66a1f281e31d20b594b5c66a2d9efcc36d979a92bb877a9678f991ff60b77e28fac55d64f21c064552a4319eb0a9a1870a76ade3c3a3534ab8353c3e57b2708363859ad3a6337fc15ffb90980d93743f972d743c3dc6fddb44279079a809abec8113a6f987f71748c036a4daf353b27a81e6983d56a2d65b71b93128d5569499d10ad1396f094eed77c044e3ce9ef82f0014c25ba693928c00b5043b641b016e3569b4bd84d683372538671307321c25e590f14bef241e6d8edf24ff39859" };
static RSAPublicKey publicKeyVector7 = { "0x00c2c4a860236d3c9096a076d6ba5107e0f7bd81e1ba916f7375724bd2b0b0b63956813715a3457ab0458b71fb35a45b27f9ef7ac3e579dea45dfbfd07819ed6b7021aa5336c58442aadd96ca9ee9d32473e9d9278562b4d10258ade6a98fb1c7cfdc3b3716ef5dec58cf73b359f389599b4b5865a9863519eb001c324387da755450db341309360e3807c0565b8e2c44fbd5e6e8d04d006d7ee768b8e8436082a90fa0e837f32f46087ab4a0d9be28aa7da1794ceb0172a7f50ed20f6df641efbcbfd2aac89775c761a7310093c671c977fa18b0d6e01fb25f7a432b42c65359784c689205719c1cf6e3a65dae2da434c326dde81bb6ffffbdbf6de5c16bba749",
                                          65537 };

static const struct RSA_OAEP_TestVectors {
  std::string name;
  RSA_SECURITY_STRENGTH keySecurityStrength;
  RSAPrivateKey privateKey;
  RSAPublicKey publicKey;
  OAEPParams parameters;
  std::string pt;
  std::string ct;
} kRSA_OAEP_TestVectors[] = {
    {   // Source [1]
        "OAEP_1024_SHA1",
        RSA_SECURITY_STRENGTH::RSA_1024,
        privateKeyVector1,
        publicKeyVector1,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "18b776ea21069d69776a33e96bad48e1dda0a5ef"),
        "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34",
        "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535fa9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a"
    },
    {   // Source [1]
        "OAEP_2048_SHA1",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector2,
        publicKeyVector2,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "47e1ab7119fee56c95ee5eaad86f40d0aa63bd33"),
        "8bba6bf82a6c0f86d5f1756e97956870b08953b06b4eb205bc1694ee",
        "53ea5dc08cd260fb3b858567287fa91552c30b2febfba213f0ae87702d068d19bab07fe574523dfb42139d68c3c5afeee0bfe4cb7969cbf382b804d6e61396144e2d0e60741f8993c3014b58b9b1957a8babcd23af854f4c356fb1662aa72bfcc7e586559dc4280d160c126785a723ebeebeff71f11594440aaef87d10793a8774a239d4a04c87fe1467b9daf85208ec6c7255794a96cc29142f9a8bd418e3c1fd67344b0cd0829df3b2bec60253196293c6b34d3f75d32f213dd45c6273d505adf4cced1057cb758fc26aeefa441255ed4e64c199ee075e7f16646182fdb464739b68ab5daff0e63e9552016824f054bf4d3c8c90a97bb6b6553284eb429fcc"
    },
    {   // Source [2]
        "OAEP_2048_SHA224_1",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector3,
        publicKeyVector3,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA224, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "00000000000000000000000000000000000000000000000000000000"),
        "313233343030",
        "2aba9ba6b55fcba1efd92069966c95ed8b567213bef9fd6bba37a7b7c502f7fed38c9cdee9fc1c221bd651f1df6f1a938a01ef80a746ca9478ae00b7ab697e2ac311425a38e4384002dea66d9824c79b56f05b00bba5b26f852a7fe27a869ef101ca73c1bf8951edfe60da5b5ca9650a2bb04640026720b8c8e94e941b1f6cfa3e9475c2ade8597515ca64077c34e896817fee30d8c80e9b4802b5c8605f7597e7f49025237989bb253e06ce5673481d36ae7f70103a4457624dfecdc953207102cdc2efd5d682907fc4812a31fcb55324b6ba2ef697b3c31cbf82a5113e1ae8fbc2afc8d63a1ac9c3a54a25cbd3db54e934402b1c5b07ea445e4d21f38ff790"
    },
    {   // Source [2]
        "OAEP_2048_SHA224_2",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector3,
        publicKeyVector3,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA224, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "313233343030",
        "8941c4670d7798f1a935da39de654e7763329afed53c9ad2c2c6f7e8214c19e8fb27ecc137be1e54b1d51f6ece4e951fa2e7f4e39a3124d9298beae8d2ae35243b83d216301c34010df33faa631b50f87fde7e4f7c34436f62df2330fee4366da95ac2bf891a9fd4fa850f7e15430b8c966ea5bdd78f5172a27df1b56716e1260f71dbc42fd4fd0b92b90e9de67f8b4ff47f20365153799ba212ffd601f0f7e674dc532ccea5619e039068990beae5f10d39e5d1f860018d25a784665d6ad50e06e59386e13b6da201980fa5aa3b642527aba012269691c773484ff2fee7a1b0a1fe6db4f1ffb1a7da8464320ebb93557c5750bef6794696b3022ea92d01bd52"
    },
    {   // Source [2]
        "OAEP_2048_SHA256_1",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector4,
        publicKeyVector4,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "0000000000000000000000000000000000000000000000000000000000000000"),
        "313233343030",
        "8e5f01ff0c1775870715fd0366a8748531f8b00803df35e0e2308db63bbec4eca4e093351876b794213b904e5dde284a82d74abfcbfff94bc9a8300bea99edd07fe97d6e0b11219f85ac15acc404d37d3da16819a14a438f3f72f8178b312526232386e918a8a7e11fc38f4668c499a00480cf9d2d75aabc0198d3ba9ba345fba9105c6564df5f6ce796f14100d186abffe4d83d57969c1caddc7c7aa340b4d1bab23d9b3982278328ddebe648f5c52588738f3c56a88b3f34c890c03fafc27f485a17677a53e974dc1dd86f463a927f4328ac51bbc61705ae8abd7f45628957489e2defd8e043b955b118fb2a1c407d45893004aae0f945f06add1e45b41a03"
    },
    {   // Source [2]
        "OAEP_2048_SHA256_2",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector4,
        publicKeyVector4,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "313233343030",
        "50c23e2ad6e3f3b10a5716cbf60efcc9f66d2c6f17bf050ba0153b877ba2755e8a0d54060034562266155744ef80547b8af777b0ff764fbb12baae49d02b4f6d65b6cd8f0a397839101d32ae163ff2e6072748d6b8017e5e73e332d53f4e91fe6233a82dbf54f3146b489803575c5ea37ab55a9ea7eae47ad4f1727d45822b569cd6e5d4b6ab759850948186616b5da2a9a316f57d899f91934bbb27edcdfa19532ba1c01f3724738daffdd88c9a18562ebcbc49185b0a817407903476d442c424c81b63aeb8f9d1b184756e0cc0a381eaba45a85c8bbc6770fd047ff1a6404a384599fbbd6a40b212a066e23f6a15cf13e42c0ea88c710e4d70c612074968e5"
    },
    {   // Source [2]
        "OAEP_3072_SHA256_1",
        RSA_SECURITY_STRENGTH::RSA_3072,
        privateKeyVector5,
        publicKeyVector5,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "0000000000000000000000000000000000000000000000000000000000000000"),
        "313233343030",
        "4f2f2db05cb302c4fb4b2eb83bd00e6fe362d4b7fae313de90374190931919727876280139e8d52efceb10003b9b367e13195d83354a30df2e3a06a743671df8761f25620790d1ab32c6ea65b74317e4cedebb725e8558d89ff6d70da36663cb34d8b0183caf9a6766b8436d2d9b0e7bb92c40483cd7cd30a681940699c8d167a4b1a0b2ba2670afeae543d34c60cd758ad7a53b8053be8bcfa471635389503b1146d051e978cd4befec148417f3b4b3cfed96ed78048452bfe88ba9b7ac4cc09ea8be3fbcfef9a818235c98a43e160f25427a5636994066ec1ac19be9fad308eb71015f417c15330083d6726977714841383bab6f44f94ef2b7313f513d3589d67d96f1b4d0887f79e414e77b77c39d5764bd7e5156193821fb80d11f7a0847d68d62e1e092d09fa4f2bb1bb65bcf407ee2d9352b3a84dffa4ec241a850466864a38518e2d5f3b51627dce6e6cf666f5f80b476ed84f96b023a63cd92229feeabdb855de9ad90cbe085190f20e6039b01a41b36f111e8faa8e0ac4578cb4fbc"
    },
    {   // Source [2]
        "OAEP_3072_SHA256_2",
        RSA_SECURITY_STRENGTH::RSA_3072,
        privateKeyVector5,
        publicKeyVector5,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "313233343030",
        "1afed89bb5df115fb1cf52de68fd4b1c895c86a6852a06002519a69c6a983e54d19351f930c227b46a6f3481b09a121bb19aeba02f2abca4b0c5aef15861f0f1d25ee3f6c0cf56eb6b3d10ec5b7640ef409d9897b32c3d3e98da2ac0089968c352838d0bc6a594786ab813c212cb72a1238014d421642839c3634ab14f61d0c775f03d875490354dd902b23752fa3bd39cda588aaedaf31b69d29895cca2bac9db554708224b753eb36c7bf11031fe9ad0462f5054750e7b5616cdfff13467b20025a71bcf4c5e6b31dea741ce589c1cfbf76cd858ee480a69dac7a306308c5d3ec8108a7efb2fae18504e72e263c0a1366103abb70cb1f7a7f01074bdca763c17d7edcbf8d64c9b0a74ef11855abbc4188451183904ef1e9647e512b302ef263123b0e4af885187d8e1eb2f6a1c65daf7b2779be15337c3386a284801cc40358c19a4d9e487896c0bbfc1e56913247e97876487d875d6bd487553552b4faf8eb4b17ddfb55a87f46b202bda0e64e480ef03e057b410b5823216f87e4709bd64"
    },
    {   // Source [2]
        "OAEP_2048_SHA384_1",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector6,
        publicKeyVector6,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA384, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        "313233343030",
        "7bd2fbe880a85da97962b4e806e3f380bba3dc80f631d9b4a9a64ab51179c5ea7f58789d8e5894b1fc7df15b34d09f5592fc600bf1edd118538a614ce3144165bf0578652686ce7df720c2660543d836746675a41cc929b198647c52ffb8b4afc74cba7de456d2298a1aa40c25247b4c1304f41bf4e137b98245ab8edea6f62077a8eadc6bc903722d0c7253b3d2b0acdc1f961157f14404dbdf50f294fd7fed64fab3a0c3cf46e683f41b89c0db6112395ff8af6348924823a43855a0cceb4bb00bb2564e40de0db8ccd803af1c4ce7873aa2fa156d09a4274b47c5888553cd09c32456da49411061e900188225eb181cf57cd8bbadf055f9f4df6f6389acd"
    },
    {   // Source [2]
        "OAEP_2048_SHA384_2",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector6,
        publicKeyVector6,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA384, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "313233343030",
        "79cb7928bcca16d8b74a0900d8de2b4e7f962e6073d74f3dff11c5a7d3e407ca962fd7eae0d3dc1ede81ea7cd4059fd1e304bf297cf30207b0abc8aa31189403d52a38811b6f11bfb930c15ec7b0e2e903623ae1d81083a5e0a7331c620d3d5b289adcbb74246d9c59336d165c0176e3c1b922d381ae8da731a933279fef6d185a689e039970135ac3c4d1d87d858e65f409341c593dd199e2dc60c16033023ad2665615877b41348721fdf3569bd03aff206a00a9705c25b3e33ff3b700ced05a6e72f3c5581eb3090c1c238ff5fcb26a286bd4c231f4eba81c5daee3c3c2dc9ac3cf2e73bcc15eef091cef335b8b89963a0d5983e1754e423d3b70c039b2c7"
    },
    {   // Source [2]
        "OAEP_2048_SHA512_1",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector7,
        publicKeyVector7,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA512, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        "313233343030",
        "acaf316a29cbd805132b0c43a4589761a54aef928e4036b15b389a9c17a04c86ee6d595c064cdabe383414e41420be7e70163d89822774374ea85befbd3f3fc7dddc3de1f1ffa2bd595dbc678a03c0ed643ab4ee540c8e3ffaf86fca0f39eb4f795e9c387045ab2f378f246a2ff746dc3cc1df8f6158f16581231514fb22f6e169b13199c4239c1827767aec256d84f729739916f7d43a015a331c56099e8d33d66df6352a459356d9d981bf467dd88fc115eb88b4b22bfcb333facc97d295d72cb06984cd12b670a539400a719d11809a73f8c4406a677eb6285da557f8f69bd006da2c286a64cbbcaf2f2a083a8e5baf560c9d6fd703ad1544413eb0c3fce7"
    },
    {   // Source [2]
        "OAEP_2048_SHA512_2",
        RSA_SECURITY_STRENGTH::RSA_2048,
        privateKeyVector7,
        publicKeyVector7,
        OAEPParams( RSA_ENCRYPTION_HASH_FUNCTIONS::SHA512, RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, "", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "313233343030",
        "e5569756d22d82b912ac15e90209006c52f6a48a499e242c6603eecfc2087c3175c4d18f42bf6bb6b201b9cebdd8a97a7b32e4e7e75e034ecb96bf0013b2f52ba036ab2929c163962f08cfd96ce780912bbebcab7798b5cb3eab91b82b01dd1983c1bee76334a71fa93ad2468a799afed4caa1284fc01225cf225bc0ceff35a6569b76b5cb57be214da94872eba8a73cd51acf917a627ef17547af38bcb805485262063f80c0daab609a40467f73fdede744db116842cfcbe4b1ea7468fcfc258e2069afaf2c552b3be864517a7b0c71d46765e9573f0643cc762ad21826920de1ab3d116496b71366b2f6eb487d8b4cf8b1d6d673da1b38fbbf1e11615b108"
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