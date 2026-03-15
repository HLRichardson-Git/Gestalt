/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * object_identifiers.h
 */

#pragma once

#include <string>

enum class RsaKeyFormat {
    PKCS1,  // Traditional RSA-specific format (PKCS#1)
    PKCS8   // Modern algorithm-agnostic format (PKCS#8)
};

enum class EccKeyFormat {
    SEC1,   // Traditional EC-specific format (SEC1 ECPrivateKey / raw uncompressed point)
    PKCS8   // Modern algorithm-agnostic format (PKCS#8 / SubjectPublicKeyInfo)
};

// RSA Algorithm OIDs
const std::string OID_RSA = "2a864886f70d010101";            // Alias for rsaEncryption
const std::string OID_RSA_ENCRYPTION = "2a864886f70d010101"; // 1.2.840.113549.1.1.1 (rsaEncryption)
const std::string OID_RSA_SSA_PSS = "2a864886f70d01010a";    // 1.2.840.113549.1.1.10 (RSASSA-PSS)
const std::string OID_RSA_OAEP = "2a864886f70d010107";       // 1.2.840.113549.1.1.7 (RSA-OAEP)

// ECDSA OIDs
const std::string OID_EC_PUBLIC_KEY = "2a8648ce3d0201";      // 1.2.840.10045.2.1 (ecPublicKey)

// Common elliptic curves
const std::string OID_SECP192R1 = "2a8648ce3d030101";        // 1.2.840.10045.3.1.1 (prime192v1/secp192r1)
const std::string OID_SECP224R1 = "2b81040021";              // 1.3.132.0.33 (secp224r1)
const std::string OID_SECP256R1 = "2a8648ce3d030107";        // 1.2.840.10045.3.1.7 (prime256v1/secp256r1)
const std::string OID_SECP384R1 = "2b81040022";              // 1.3.132.0.34 (secp384r1)
const std::string OID_SECP521R1 = "2b81040023";              // 1.3.132.0.35 (secp521r1)
const std::string OID_SECP256K1 = "2b8104000a";              // 1.3.132.0.10 (secp256k1)

// Hash algorithm OIDs (for signature verification)
const std::string OID_SHA256 = "608648016503040201";         // 2.16.840.1.101.3.4.2.1
const std::string OID_SHA384 = "608648016503040202";         // 2.16.840.1.101.3.4.2.2
const std::string OID_SHA512 = "608648016503040203";         // 2.16.840.1.101.3.4.2.3