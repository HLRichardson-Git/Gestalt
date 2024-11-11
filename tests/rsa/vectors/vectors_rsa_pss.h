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

/*
 * Test Vector sources:
 *  [1] https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/pss-int.txt
 *  [2] https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures#rsa2vs
 *
*/

// Source [1]
static BigInt p = "0xd17f655bf27c8b16d35462c905cc04a26f37e2a67fa9c0ce0dced472394a0df743fe7f929e378efdb368eddff453cf007af6d948e0ade757371f8a711e278f6b";
static BigInt q = "0xc6d92b6fee7414d1358ce1546fb62987530b90bd15e0f14963a5e2635adb69347ec0c01b2ab1763fd8ac1a592fb22757463a982425bb97a3a437c5bf86d03f2f";
static BigInt d = "0x050e2c3e38d886110288dfc68a9533e7e12e27d2aa56d2cdb3fb6efa990bcff29e1d2987fb711962860e7391b1ce01ebadb9e812d2fbdfaf25df4ae26110a6d7a26f0b810f54875e17dd5c9fb6d641761245b81e79f8c88f0e55a6dcd5f133abd35f8f4ec80adf1bf86277a582894cb6ebcd2162f1c7534f1f4947b129151b71";

static BigInt n = "0xa2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe888b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de7751222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5";
static BigInt e = 65537;

static RSAPrivateKey privateKeyVector = { d, p, q };
static RSAPublicKey publicKeyVector = { n, e };

// Source [2]
static RSAPrivateKey privateKeyVector1 = { "0x49e5786bb4d332f94586327bde088875379b75d128488f08e574ab4715302a87eea52d4c4a23d8b97af7944804337c5f55e16ba9ffafc0c9fd9b88eca443f39b7967170ddb8ce7ddb93c6087c8066c4a95538a441b9dc80dc9f7810054fd1e5c9d0250c978bb2d748abe1e9465d71a8165d3126dce5db2adacc003e9062ba37a54b63e5f49a4eafebd7e4bf5b0a796c2b3a950fa09c798d3fa3e86c4b62c33ba9365eda054e5fe74a41f21b595026acf1093c90a8c71722f91af1ed29a41a2449a320fc7ba3120e3e8c3e4240c04925cc698ecd66c7c906bdf240adad972b4dff4869d400b5d13e33eeba38e075e872b0ed3e91cc9c283867a4ffc3901d2069f" };
static RSAPublicKey publicKeyVector1 = { "0xc5062b58d8539c765e1e5dbaf14cf75dd56c2e13105fecfd1a930bbb5948ff328f126abe779359ca59bca752c308d281573bc6178b6c0fef7dc445e4f826430437b9f9d790581de5749c2cb9cb26d42b2fee15b6b26f09c99670336423b86bc5bec71113157be2d944d7ff3eebffb28413143ea36755db0ae62ff5b724eecb3d316b6bac67e89cacd8171937e2ab19bd353a89acea8c36f81c89a620d5fd2effea896601c7f9daca7f033f635a3a943331d1b1b4f5288790b53af352f1121ca1bef205f40dc012c412b40bdd27585b946466d75f7ee0a7f9d549b4bece6f43ac3ee65fe7fd37123359d9f1a850ad450aaf5c94eb11dea3fc0fc6e9856b1805ef",
                                          8833359 };
// Source [2]
static RSAPrivateKey privateKeyVector2 = { "0x073a5fc4cd642f6113dffc4f84035cee3a2b8acc549703751a1d6a5eaa13487229a58ef7d7a522bb9f4f25510f1aa0f74c6a8fc8a5c5be8b91a674ede50e92f7e34a90a3c9da999fffb1d695e4588f451256c163484c151350cb9c7825a7d910845ee5cf826fecf9a7c0fbbbba22bb4a531c131d2e7761ba898f002ebef8ab87218511f81d3266e1ec07a7ca8622514c6dfdc86c67679a2c8f5f031de9a0c22b5a88060b46ee0c64d3b9af3c0a379bcd9c6a1b51cf6480456d3fd6def94cd2a6c171dd3f010e3c9d662bc857208248c94ebcb9fd997b9ff4a7e5fd95558569906525e741d78344f6f6cfdbd59d4faa52ee3fa964fb7cccb2d6be1935d211fe1498217716273939a946081fd8509913fd47747c5c2f03efd4d6fc9c6fcfd8402e9f40a0a5b3de3ca2b3c0fac9456938faa6cf2c20e3912e5981c9876d8ca1ff29b87a15eeae0ccce3f8a8f1e405091c083b98bcc5fe0d0deaae33c67c0394437f0eccb385b7efb17aeebba8afaecca30a2f63eac8f0ac8f1eacad85bbcaf3960b" };
static RSAPublicKey publicKeyVector2 = { "0xa7a1882a7fb896786034d07fb1b9f6327c27bdd7ce6fe39c285ae3b6c34259adc0dc4f7b9c7dec3ca4a20d3407339eedd7a12a421da18f5954673cac2ff059156ecc73c6861ec761e6a0f2a5a033a6768c6a42d8b459e1b4932349e84efd92df59b45935f3d0e30817c66201aa99d07ae36c5d74f408d69cc08f044151ff4960e531360cb19077833adf7bce77ecfaa133c0ccc63c93b856814569e0b9884ee554061b9a20ab46c38263c094dae791aa61a17f8d16f0e85b7e5ce3b067ece89e20bc4e8f1ae814b276d234e04f4e766f501da74ea7e3817c24ea35d016676cece652b823b051625573ca92757fc720d254ecf1dcbbfd21d98307561ecaab545480c7c52ad7e9fa6b597f5fe550559c2fe923205ac1761a99737ca02d7b19822e008a8969349c87fb874c81620e38f613c8521f0381fe5ba55b74827dad3e1cf2aa29c6933629f2b286ad11be88fa6436e7e3f64a75e3595290dc0d1cd5eee7aaac54959cc53bd5a934a365e72dd81a2bd4fb9a67821bffedf2ef2bd94913de8b",
                                          1316263 };                                           

static const struct RSA_PSS_TestVectors {
  std::string name;
  RSASecurityStrength keySecurityStrength;
  RSAPrivateKey privateKey;
  RSAPublicKey publicKey;
  PSSParams parameters;
  std::string pt;
  std::string ct;
} kRSA_PSS_TestVectors[] = {
    {   // Source [1]
        "PSS_1024_SHA1",
        RSASecurityStrength::RSA_1024,
        privateKeyVector,
        publicKeyVector,
        PSSParams(HashAlgorithm::SHA1, RSA_MGF_FUNCTIONS::MGF1, 20, "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"),
        "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc",
        "8daa627d3de7595d63056c7ec659e54406f10610128baae821c8b2a0f3936d54dc3bdce46689f6b7951bb18e840542769718d5715d210d85efbb596192032c42be4c29972c856275eb6d5a45f05f51876fc6743deddd28caec9bb30ea99e02c3488269604fe497f74ccd7c7fca1671897123cbd30def5d54a2b5536ad90a747e"
    },
    {   // Source [2]
        "PSS_2048_SHA224",
        RSASecurityStrength::RSA_2048,
        privateKeyVector1,
        publicKeyVector1,
        PSSParams(HashAlgorithm::SHA224, RSA_MGF_FUNCTIONS::MGF1, 15, "463729b3eaf43502d9cff129925681"),
        "37ddd9901478ae5c16878702cea4a19e786d35582de44ae65a16cd5370fbe3ffdd9e7ee83c7d2f27c8333bbe1754f090059939b1ee3d71e020a675528f48fdb2cbc72c65305b65125c796162e7b07e044ed15af52f52a1febcf4237e6aa42a69e99f0a9159daf924bba12176a57ef4013a5cc0ab5aec83471648005d67d7122e",
        "7e628bcbe6ff83a937b8961197d8bdbb322818aa8bdf30cdfb67ca6bf025ef6f09a99dba4c3ee2807d0b7c77776cfeff33b68d7e3fa859c4688626b2441897d26e5d6b559dd72a596e7dad7def9278419db375f7c67cee0740394502212ebdd4a6c8d3af6ee2fd696d8523de6908492b7cbf2254f15a348956c19840dc15a3d732ef862b62ede022290de3af11ca5e79a3392fff06f75aca8c88a2de1858b35a216d8f73fd70e9d67958ed39a6f8976fb94ec6e61f238a52f9d42241e8354f89e3ece94d6fa5bfbba1eeb70e1698bff31a685fbe799fb44efe21338ed6eea2129155aabc0943bc9f69a8e58897db6a8abcc2879d5d0c5d3e6dc5eb48cf16dac8"
    },
    {   // Source [2]
        "PSS_2048_SHA256",
        RSASecurityStrength::RSA_2048,
        privateKeyVector1,
        publicKeyVector1,
        PSSParams(HashAlgorithm::SHA256, RSA_MGF_FUNCTIONS::MGF1, 20, "e1256fc1eeef81773fdd54657e4007fde6bcb9b1"),
        "fd6a063e61c2b354fe8cb37a5f3788b5c01ff15a725f6b8181e6f6b795ce1cf316e930cc939cd4e865f0bdb88fe6bb62e90bf3ff7e4d6f07320dda09a87584a0620cada22a87ff9ab1e35c7977b0da88eab00ca1d2a0849fec569513d50c5e392afc032aee2d3e522c8c1725dd3eef0e0b35c3a83701af31f9e9b13ce63bb0a5",
        "492b6f6884df461fe10516b6b8cc205385c20108ec47d5db69283f4a7688e318cfdc3c491fb29225325aeb46efc75e855840910bbaf0d1c8d4784542b970754aaa84bfe47c77b3a1b5037d4d79759471e96cc7a527a0ed067e21709ef7f4c4111b60b8c08082c8180c7c96b61c0f7102ed9b90e24de11e6298bb244518f9b446ce641fe995e9cc299ed411b65eb25eaae9e553484a0a7e956eadf0840888c70e5ca6ebc3e479f8c69c53cf31370ab385e8b673dc45a0c1964ec49468d18246213a8f93a2a96aad5a2701c191a14a31519e4f36544d668708ff37be5481cb0ffa2b0e1f145e29f8575dfa9ec30c6cb41c393439292210ea806a505598ebdf0833"
    },
    {   // Source [2]
        "PSS_2048_SHA384",
        RSASecurityStrength::RSA_2048,
        privateKeyVector1,
        publicKeyVector1,
        PSSParams(HashAlgorithm::SHA384, RSA_MGF_FUNCTIONS::MGF1, 25, "b750587671afd76886e8ffb7865e78f706641b2e4251b48706"),
        "833aa2b1dcc77607a44e804ee77d45408586c536861f6648adcd2fb65063368767c55c6fe2f237f6404250d75dec8fa68bcaf3b6e561863ae01c91aa23d80c6999a558a4c4cb317d540cde69f829aad674a89812f4d353689f04648c7020a73941620018295a4ae4083590cc603e801867a51c105a7fb319130f1022de44f13e",
        "2ca37a3d6abd28c1eaf9bde5e7ac17f1fa799ce1b4b899d19985c2ff7c8ba959fe54e5afb8bc4021a1f1c687eebb8cba800d1c51636b1f68dc3e48f63e2da6bc6d09c6668f68e508c5d8c19bef154759e2f89ade152717370a8944f537578296380d1fe6be809e8b113d2b9d89e6a46f5c333d4fd48770fc1ea1c548104575b84cf071042bfe5acf496392be8351a41c46a2cab0864c4c1c5b5e0c7b27e7b88c69f37ffa7e1a8cd98f343ac84a4ad67025a40ed8f664e9d630337de6e48bb2125e2552123609491f183afd92634487f0b2cf971f2626e88858879d45a29b0fefb66cd41b2e4e968385bd9fc8c7211976bc6bd3e1ad6df60856985a825f4726d2"
    },
    {   // Source [2]
        "PSS_2048_SHA512",
        RSASecurityStrength::RSA_2048,
        privateKeyVector1,
        publicKeyVector1,
        PSSParams(HashAlgorithm::SHA512, RSA_MGF_FUNCTIONS::MGF1, 30, "aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac"),
        "5f0fe2afa61b628c43ea3b6ba60567b1ae95f682076f01dfb64de011f25e9c4b3602a78b94cecbc14cd761339d2dc320dba504a3c2dcdedb0a78eb493bb11879c31158e5467795163562ec0ca26c19e0531530a815c28f9b52061076e61f831e2fc45b86631ea7d3271444be5dcb513a3d6de457a72afb67b77db65f9bb1c380",
        "5e0712bb363e5034ef6b23c119e3b498644445faab5a4c0b4e217e4c832ab34c142d7f81dbf8affdb2dacefabb2f83524c5aa883fc5f06e528b232d90fbea9ca08ae5ac180d477eaed27d137e2b51bd613b69c543d555bfc7cd81a4f795753c8c64c6b5d2acd9e26d6225f5b26e4e66a945fd6477a277b580dbeaa46d0be498df9a093392926c905641945ec5b9597525e449af3743f80554788fc358bc0401a968ff98aaf34e50b352751f32274750ff5c1fba503050204cec9c77deede7f8fa20845d95f5177030bc91d51f26f29d2a65b870dc72b81e5ef9eeef990d7c7145bbf1a3bc7aedd19fa7cbb020756525f1802216c13296fd6aac11bf2d2d90494"
    },
    {   // Source [2]
        "PSS_3072_SHA224",
        RSASecurityStrength::RSA_3072,
        privateKeyVector2,
        publicKeyVector2,
        PSSParams(HashAlgorithm::SHA224, RSA_MGF_FUNCTIONS::MGF1, 28, "3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53"),
        "c8ed14895c80a91fda8367cf4aee386b8a378645f06afee72f7c94047fddc7aef84c26c83fef13bf65a3c7750c91967ecc02748fd574b933d5ec21c01c8f178afe6c3356789d0112178e04c3169cfabec6e2621b334f3c6705fc1099a4bd3147a0f7431a4fb1fb80b8ed26a0af38ed93428057d154260fe98854687661919e4e",
        "27b4f0aa139565fbd7860760610f6866d5b5f0d777921f06f5053291123e3b259d67294ccb8c0d068b8dae360aad2cf7d07296b539e4d2e9b08c343286d522f7dd63c6620e8672be492f3b039f73d88ab9d22a5463cd1f07d688e8ba3fbad531b0c3870ccbfebb596ce4ec643d309744bdbd675d5841284cbac902cfb70ade6d33946d8dc6109bbbc42412db25b8c62222c5ff94f8eb868982265392a44e807474910b4b39558bbef33197907178ce146fdd7e94092ad58bf41a474e626136789fc2fe6374a1b5fefddd5fecb7f8ca5893220d1ab9e822c3ae8adda1ebaddb18a6a12bfc165d12071441a991377cee6dc8e50839497346fee13f12c5b7b6d024b8ecfdad80d5ef6e9e4996ac21c4eb6036bb51f5be5e38f265181154000824e3c1f231d18589ccdaee90fe307ba56324318b5358468e9f3913b83ab8b34d949629ed7839f8da85bdcda52f3da5a419f777b3860dbf2ffe28d96244312549528a20cc7399fc010844365806167fe43235521c909587c2c7b8db4e296dad2aefa2"
    },
    {   // Source [2]
        "PSS_3072_SHA256",
        RSASecurityStrength::RSA_3072,
        privateKeyVector2,
        publicKeyVector2,
        PSSParams(HashAlgorithm::SHA256, RSA_MGF_FUNCTIONS::MGF1, 32, "3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc"),
        "c16499110ed577202aed2d3e4d51ded6c66373faef6533a860e1934c63484f87a8d9b92f3ac45197b2909710abba1daf759fe0510e9bd8dd4d73cec961f06ee07acd9d42c6d40dac9f430ef90374a7e944bde5220096737454f96b614d0f6cdd9f08ed529a4ad0e759cf3a023dc8a30b9a872974af9b2af6dc3d111d0feb7006",
        "4335707da735cfd10411c9c048ca9b60bb46e2fe361e51fbe336f9508dc945afe075503d24f836610f2178996b52c411693052d5d7aed97654a40074ed20ed6689c0501b7fbac21dc46b665ac079760086414406cd66f8537d1ebf0dce4cf0c98d4c30c71da359e9cd401ff49718fdd4d0f99efe70ad8dd8ba1304cefb88f24b0eedf70116da15932c76f0069551a245b5fc3b91ec101f1d63b9853b598c6fa1c1acdbacf9626356c760119be0955644301896d9d0d3ea5e6443cb72ca29f4d45246d16d74d00568c219182feb191179e4593dc152c608fd80536329a533b3a631566814cd654f587c2d8ce696085e6ed1b0b0278e60a049ec7a399f94fccae6462371a69695ef525e00936fa7d9781f9ee289d4105ee827a27996583033cedb2f297e7b4926d906ce0d09d84128406ab33d7da0f8a1d4d2f666568686c394d139b0e5e99337758de85910a5fa25ca2aa6d8fb1c777244e7d98de4c79bbd426a5e6f657e37477e01247432f83797fbf31b50d02b83f69ded26d4945b2bc3f86e"
    },
    {   // Source [2]
        "PSS_3072_SHA384",
        RSASecurityStrength::RSA_3072,
        privateKeyVector2,
        publicKeyVector2,
        PSSParams(HashAlgorithm::SHA384, RSA_MGF_FUNCTIONS::MGF1, 48, "61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452"),
        "752a9916f449aebf814ce59ca6e82fa8038e4685419241c1488c6659b2ff3f7b7f38f0900a79c77a3b57151aff613c16f5020ad96ba945db88268722ca584c09b4054a40c00901149bb392f0916cd4244699a5e6a8c37e9621f54b471166797a7b58502cff4083140827052646501f5b5f1bc0b4e129147d7cc157cf6e73ec58",
        "6646a88ee4b845da4931274c23840dada6145fe0af954829d1d56661546a25e46316e216bb6b9446b368884ba14969a6f68ccbc1cf5b4e7a6d3aabec67f64963f63b088fa817c855d776ddcada57e5daa50fc1c877389c3cb9d99095a869a963bc91ec24b2422ef6b8dd18fd20d2b215fee6e98cda415ae44d2d2616fe1708292a3ef50a075170b3a7ebab02918ab0301794c17fb35e2038f369d94dd49569c066f7c392889dc4b878c50c7e52586b5081114d202338d23304f16f912d519a9ad21baff0e3d21761f373d08421e10108a983048fcb90eb2adc7c7f12ffa1571b091c781b255a77a880e97975f14f42baf5aa285ecc142157c3e1addd6aa0c09253a11c59144abd3b1e212d89e27ed96fb75756afc20ec67423b151194cb0b0648c659987a5583cb7757779d8a39e205e7101a5351ce1af2c9c6b0847cca57af52593323905e3d2297c0d54541a0125621640fe1deef13e759f8f6c56a2ec2a94831ac2c614b911e79edd542fef651f5a827f480575ae220c495f2a2842f99ec4"
    },
    {   // Source [2]
        "PSS_3072_SHA512",
        RSASecurityStrength::RSA_3072,
        privateKeyVector2,
        publicKeyVector2,
        PSSParams(HashAlgorithm::SHA512, RSA_MGF_FUNCTIONS::MGF1, 62, "2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783"),
        "44240ce519f00239bd66ba03c84d3160b1ce39e3932866e531a62b1c37cf4170c3dc4809236fb1ade181db49fc9c7ccd794b433d1ad0bc056e14738e0ae45c0e155972a40a989fa4b9bcdc308f11990818835fa2c256b47ee4173fb4fed22ccf4385d2dd54d593c74f0004df08134eb8965dd53a122317f59b95d6b69d017958",
        "8f47abc2326e22cf62404508b442e81ad45afff7274096b9a13e478cdd0a72f99a76bf517f1bb0f872a523d8c588d4402569e948fd6a108ae1a45c65830828a10e94d432765314ba82ead310fc87ac99a5b39f30ab8820bf69e6934a9c1c915c19f36ea7717eaff7af67b4991315b1873ba929bedf18a975be808e7aa14a6726126c79cc93f69541c5cefdeb5b67ec279d8f5a446583e4b4faed1685140ee4b3b757c8ff4a1ef9cd76a88e05319ee62003d2d77290c94c579b0ca2ab0deb3176ef10a3fdb85c80ffbc9e2a665a23744fc836f9a9a103cd9fb756952356a2f1acdd68a645e20179006558b5d4d0b9b0bd3adf5e290f49dae60b9d19920953ea8bb237d5b3dcfe149a60f12a4ee3a889b33bcd3a3b753d610757cbcd093dd5a734255333689695ab636963e3d215a8e77ff31973718a4944a1e9e44f45754d39f6fa431c53f9a2ef36e16a5f70636eb5fba54e15c20a714f2809a7cff4b8dc1165f836607eb5a5a3bb0c4567eee26941fef46fb41e73b565c0cf8c72e404221264"
    }
};

// Define a custom name generator function
inline std::string CustomNameGenerator(const testing::TestParamInfo<RSA_PSS_TestVectors>& info) {
    const RSA_PSS_TestVectors& test = info.param;
    return test.name;
}
class RSA_PSS_Test : public testing::TestWithParam<RSA_PSS_TestVectors> {};

INSTANTIATE_TEST_SUITE_P(RSA_Padding_Signature, RSA_PSS_Test, testing::ValuesIn(kRSA_PSS_TestVectors), CustomNameGenerator);