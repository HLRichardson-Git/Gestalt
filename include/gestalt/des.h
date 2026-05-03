/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.h
 *
 * This file contains the definitions of Gestalts DES & 3DES security functions.
 */

#pragma once

#include <gestalt/secure_bytes.h>

SecureBytes encryptDESECB(const SecureBytes& plaintext, const SecureBytes& key);
SecureBytes decryptDESECB(const SecureBytes& ciphertext, const SecureBytes& key);
SecureBytes encrypt3DESECB(
    const SecureBytes& plaintext,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);
SecureBytes decrypt3DESECB(
    const SecureBytes& ciphertext,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);

SecureBytes encryptDESCBC(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes decryptDESCBC(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes encrypt3DESCBC(
    const SecureBytes& plaintext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);
SecureBytes decrypt3DESCBC(
    const SecureBytes& ciphertext,
    const SecureBytes& iv,
    const SecureBytes& key1,
    const SecureBytes& key2,
    const SecureBytes& key3
);

SecureBytes encryptDESCTR(const SecureBytes& plaintext, const SecureBytes& iv, const SecureBytes& key);
SecureBytes decryptDESCTR(const SecureBytes& ciphertext, const SecureBytes& iv, const SecureBytes& key);
