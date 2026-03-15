
#include "pem.h"
#include "../der/der.h"
#include "utils.h"

std::vector<uint8_t> PEMDecoder::extractDER(const std::string& pem, const std::string& expectedHeader) {
    std::string begin = "-----BEGIN " + expectedHeader + "-----";
    std::string end   = "-----END " + expectedHeader + "-----";

    auto b = pem.find(begin);
    auto e = pem.find(end);

    if (b == std::string::npos || e == std::string::npos)
        throw std::runtime_error("Invalid PEM header");

    auto headerEnd = pem.find('\n', b);
    if (headerEnd == std::string::npos)
        throw std::runtime_error("Invalid PEM header formatting");

    size_t bodyStart = headerEnd + 1;

    std::string b64;

    for (size_t i = bodyStart; i < e; ++i) {
        if (pem[i] != '\n' && pem[i] != '\r')
            b64.push_back(pem[i]);
    }

    return base64Decode(b64);
}

RSAPublicKey PEMDecoder::decodeRSAPublicKeyFromPKCS1(const std::string& pem) {
    auto der = extractDER(pem, "RSA PUBLIC KEY");
    DERDecoder decoder(der);
    return decoder.decodeRSAPublicKeyFromPKCS1();
}

RSAPublicKey PEMDecoder::decodeRSAPublicKeyFromPKCS8(const std::string& pem) {
    auto der = extractDER(pem, "PUBLIC KEY");
    DERDecoder decoder(der);
    return decoder.decodeRSAPublicKeyFromPKCS8();
}

RSAKeyPair PEMDecoder::decodeRSAPrivateKeyFromPKCS1(const std::string& pem) {
    auto der = extractDER(pem, "RSA PRIVATE KEY");
    DERDecoder decoder(der);
    return decoder.decodeRSAPrivateKeyFromPKCS1();
}

RSAKeyPair PEMDecoder::decodeRSAPrivateKeyFromPKCS8(const std::string& pem) {
    auto der = extractDER(pem, "PRIVATE KEY");
    DERDecoder decoder(der);
    return decoder.decodeRSAPrivateKeyFromPKCS8();
}

ECDSAPublicKey PEMDecoder::decodeECPublicKeyFromSEC1(const std::string& pem) {
    auto der = extractDER(pem, "EC PUBLIC KEY");
    DERDecoder decoder(der);
    return decoder.decodeECPublicKeyFromSEC1();
}

ECDSAPublicKey PEMDecoder::decodeECPublicKeyFromPKCS8(const std::string& pem) {
    auto der = extractDER(pem, "PUBLIC KEY");
    DERDecoder decoder(der);
    return decoder.decodeECPublicKeyFromPKCS8();
}

KeyPair PEMDecoder::decodeECPrivateKeyFromSEC1(const std::string& pem) {
    auto der = extractDER(pem, "EC PRIVATE KEY");
    DERDecoder decoder(der);
    return decoder.decodeECPrivateKeyFromSEC1();
}

KeyPair PEMDecoder::decodeECPrivateKeyFromPKCS8(const std::string& pem) {
    auto der = extractDER(pem, "PRIVATE KEY");
    DERDecoder decoder(der);
    return decoder.decodeECPrivateKeyFromPKCS8();
}
