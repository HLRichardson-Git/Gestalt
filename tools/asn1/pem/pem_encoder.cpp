
#include "pem.h"
#include "../der/der.h"
#include "utils.h"

std::string PEMEncoder::wrapDER(const std::vector<uint8_t>& der, const std::string& header) {
    std::string b64 = base64Encode(der);

    std::string body;
    for (size_t i = 0; i < b64.size(); ++i) {
        body.push_back(b64[i]);
        if ((i + 1) % 64 == 0)
            body.push_back('\n');
    }
    if (!body.empty() && body.back() != '\n')
        body.push_back('\n');

    return "-----BEGIN " + header + "-----\n" +
           body +
           "-----END " + header + "-----\n";
}

std::string PEMEncoder::encodeRSAPublicKeyToPKCS1(const RSAPublicKey& key) {
    DEREncoder encoder;
    auto der = encoder.encodeRSAPublicKeyToPKCS1(key);
    return wrapDER(der, "RSA PUBLIC KEY");
}

std::string PEMEncoder::encodeRSAPublicKeyToPKCS8(const RSAPublicKey& key) {
    DEREncoder encoder;
    auto der = encoder.encodeRSAPublicKeyToPKCS8(key);
    return wrapDER(der, "PUBLIC KEY");
}

std::string PEMEncoder::encodeRSAPrivateKeyToPKCS1(const RSAKeyPair& key) {
    DEREncoder encoder;
    auto der = encoder.encodeRSAPrivateKeyToPKCS1(key);
    return wrapDER(der, "RSA PRIVATE KEY");
}

std::string PEMEncoder::encodeRSAPrivateKeyToPKCS8(const RSAKeyPair& key) {
    DEREncoder encoder;
    auto der = encoder.encodeRSAPrivateKeyToPKCS8(key);
    return wrapDER(der, "PRIVATE KEY");
}
